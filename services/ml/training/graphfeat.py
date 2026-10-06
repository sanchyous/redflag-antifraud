"""Графовый анализ сети вызовов (NetworkX) — офлайн, в обучении. Не модельный признак: ядро
Go считает «веер» онлайн на окнах (internal/detection/graph/fan.go) и это остаётся горячим путём
продакшена. Здесь — независимая, более дорогая проверка той же идеи на полном графе набора:
(1) общая структура сети для отчёта (компоненты, степени, сообщества) и (2) сверка с эвристикой
Go — насколько онлайн-версия, ограниченная окном, соответствует офлайн-анализу по всему набору.
Расхождение ожидаемо и само по себе информативно: показывает, что именно теряет окно.

ADR-0018. Использует caller/callee из экспорта (cmd/export, см. ADR) — не маскированные значения
и не персональные данные в проде: это обучающий набор на синтетике либо выгрузке организаторов,
не продакшен-трафик, наружу (API, панель) эти графы не публикуются.
"""

from __future__ import annotations

import networkx as nx
import pandas as pd


def build_call_graph(df: pd.DataFrame) -> nx.MultiDiGraph:
    """Ориентированный мультиграф вызовов caller -> callee по строкам одного набора (train/calib/test
    собираются независимо: графы наборов не пересекаются, иначе оценка завышена утечкой — тот же
    принцип, что и у разбиения по номерам в обучении CatBoost)."""
    g = nx.MultiDiGraph()
    if "caller" not in df.columns or "callee" not in df.columns:
        return g
    sub = df[["caller", "callee"]].dropna()
    sub = sub[(sub["caller"] != "") & (sub["callee"] != "")]
    g.add_edges_from(zip(sub["caller"], sub["callee"], strict=True))
    return g


def graph_summary(g: nx.MultiDiGraph) -> dict:
    """Структура сети вызовов целиком: компоненты, степени, сообщества (greedy modularity).
    Для отчёта — не для принятия решений по конкретному вызову."""
    if g.number_of_nodes() == 0:
        return {"nodes": 0, "edges": 0}
    ug = nx.Graph(g)  # неориентированная проекция: компоненты и сообщества считаются без учёта направления
    sizes = sorted((len(c) for c in nx.connected_components(ug)), reverse=True)
    # степень только среди вызывающих (out_degree > 0): получателей в графе обычно на порядок больше,
    # и они дают нулевую исходящую степень по построению — иначе медиана по всем узлам бессмысленна
    out_degrees = [d for _, d in g.out_degree() if d > 0]
    deg = pd.Series(out_degrees) if out_degrees else pd.Series([0])
    communities, modularity = None, None
    try:
        # cutoff ограничивает число итераций greedy-слияния — граф может быть крупным (сотни тысяч вызовов)
        found = nx.algorithms.community.greedy_modularity_communities(
            ug, cutoff=1, best_n=min(50, ug.number_of_nodes())
        )
        communities = len(found)
        modularity = round(float(nx.algorithms.community.modularity(ug, found)), 4)
    except Exception:
        pass  # сообщества — необязательная часть отчёта; остальная сводка не должна падать из-за них
    return {
        "nodes": g.number_of_nodes(),
        "edges": g.number_of_edges(),
        "components": len(sizes),
        "largest_component": sizes[0] if sizes else 0,
        "components_top10": sizes[:10],
        "out_degree_p50": float(deg.median()),
        "out_degree_p99": float(deg.quantile(0.99)),
        "communities": communities,
        "modularity": modularity,
    }


_FAN_COLS = {"caller", "callee", "r_out_calls_1h", "r_out_unanswered_share", "r_out_short_share", "r_foreign_ingress"}


def detect_fans(
    df: pd.DataFrame, *, min_calls: int = 30, min_group: int = 4, min_disjoint: float = 0.85, max_candidates: int = 1500
) -> tuple[set[str], dict]:
    """Независимая от Go реализация «веера» (docs/theory.md §3): группа номеров с аномальным
    шаблоном (много коротких/неотвеченных вызовов или вход из-за рубежа) и почти непересекающимися
    списками адресатов. Признаки шаблона уже посчитаны Go (`r_*`), граф похожести списков — NetworkX.

    O(n²) по числу «аномальных» кандидатов (попарный Jaccard списков адресатов), поэтому при большом
    наборе берутся top max_candidates по числу вызовов — честно отражается в возвращаемой диагностике,
    а не скрывается молча."""
    if not _FAN_COLS.issubset(df.columns) or df.empty:
        return set(), {"candidates": 0, "capped": False}
    g = df.groupby("caller").agg(
        calls=("callee", "count"),
        unans=("r_out_unanswered_share", "max"),
        short=("r_out_short_share", "max"),
        foreign=("r_foreign_ingress", "max"),
        peers=("callee", lambda s: frozenset(s)),
    )
    g = g[g["calls"] >= min_calls]
    anomalous = g[(g["unans"] >= 0.5) | (g["short"] >= 0.5) | (g["foreign"] >= 1)]
    capped = len(anomalous) > max_candidates
    if capped:
        anomalous = anomalous.nlargest(max_candidates, "calls")
    diag = {"candidates": len(anomalous), "capped": capped}
    if anomalous.empty:
        return set(), diag

    # граф похожести: ребро между двумя вызывающими из когорты, если их списки адресатов практически
    # не пересекаются (|union| / сумма длин ≥ min_disjoint) — ядро идеи «веера»
    sim = nx.Graph()
    sim.add_nodes_from(anomalous.index)
    callers = list(anomalous.index)
    peers = anomalous["peers"]
    for i in range(len(callers)):
        pi = peers.iat[i]
        if not pi:
            continue
        for j in range(i + 1, len(callers)):
            pj = peers.iat[j]
            total = len(pi) + len(pj)
            if total == 0:
                continue
            disjoint = len(pi | pj) / total
            if disjoint >= min_disjoint:
                sim.add_edge(callers[i], callers[j])

    fans: set[str] = set()
    for comp in nx.connected_components(sim):
        if len(comp) >= min_group:
            fans |= comp
    return fans, diag


def validate_against_go(df: pd.DataFrame, fans: set[str], diag: dict) -> dict:
    """Сравнивает графовую (NetworkX, видит весь набор) разметку веера с флагом fan_member боевого
    движка (Go, видит только скользящее окно). Расхождение — не ошибка, а честная граница online-эвристики."""
    if "r_fan_member" not in df.columns:
        return {"available": False}
    by_caller = df.groupby("caller")["r_fan_member"].max() > 0
    go_fans = set(by_caller[by_caller].index)
    both = fans & go_fans
    return {
        "available": True,
        "networkx_fans": len(fans),
        "go_fans": len(go_fans),
        "agree": len(both),
        "only_go": len(go_fans - fans),
        "only_networkx": len(fans - go_fans),
        "agreement_rate": round(len(both) / len(fans), 4) if fans else None,
        **diag,
    }


def analyze(df: pd.DataFrame) -> dict:
    """Собирает графовый раздел отчёта обучения целиком. Не бросает исключений — графовый анализ
    вспомогательный, его сбой не должен ронять обучение модели."""
    try:
        if "caller" not in df.columns or "callee" not in df.columns:
            return {"available": False, "reason": "в наборе нет caller/callee (старый экспорт?)"}
        body = df[df["emergency"] == 0] if "emergency" in df.columns else df
        g = build_call_graph(body)
        if g.number_of_nodes() == 0:
            return {"available": False, "reason": "пустой граф"}
        fans, diag = detect_fans(body)
        return {"available": True, "summary": graph_summary(g), "fan_validation": validate_against_go(body, fans, diag)}
    except Exception as e:  # отчёт не должен падать из-за вспомогательного графового раздела
        return {"available": False, "reason": f"graphfeat: {e}"}
