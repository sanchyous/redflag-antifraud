"""Графовый анализ (NetworkX): построение графа, сводка, обнаружение «веера», сверка с Go."""

from __future__ import annotations

import pandas as pd

from training import graphfeat as GF


def _fan_df() -> pd.DataFrame:
    """5 вызывающих с аномальным шаблоном (много коротких, неотвеченных) и непересекающимися
    списками адресатов — классический «веер»; плюс один обычный вызывающий (общий пул клиентов,
    как у колл-центра) — не должен попасть в веер, несмотря на тот же объём трафика."""
    rows = []
    for c in range(5):
        caller = f"fan{c}"
        for i in range(40):
            rows.append(
                {
                    "caller": caller,
                    "callee": f"peer-{c}-{i}",  # у каждого — свой непересекающийся пул
                    "r_out_calls_1h": 40.0,
                    "r_out_unanswered_share": 0.8,
                    "r_out_short_share": 0.9,
                    "r_foreign_ingress": 0.0,
                    "r_fan_member": 0.0,  # Go НЕ нашёл (окно уже; проверяем расхождение)
                    "emergency": 0,
                }
            )
    # обычный колл-центр: нормальный шаблон (мало коротких/неотвеченных) — вне когорты «аномальных»
    # ещё до проверки непересечения списков; реалистично — колл-центры не бросают трубку массово
    pool = [f"client-{i}" for i in range(30)]
    for i in range(40):
        rows.append(
            {
                "caller": "callcenter",
                "callee": pool[i % len(pool)],
                "r_out_calls_1h": 40.0,
                "r_out_unanswered_share": 0.2,
                "r_out_short_share": 0.1,
                "r_foreign_ingress": 0.0,
                "r_fan_member": 0.0,
                "emergency": 0,
            }
        )
    return pd.DataFrame(rows)


def test_build_call_graph_counts_nodes_and_edges():
    g = GF.build_call_graph(_fan_df())
    assert g.number_of_edges() == 5 * 40 + 40
    assert g.number_of_nodes() == 5 + 5 * 40 + 1 + 30  # вызывающие + их адресаты + колл-центр + его пул


def test_build_call_graph_empty_without_columns():
    g = GF.build_call_graph(pd.DataFrame({"x": [1, 2]}))
    assert g.number_of_nodes() == 0


def test_detect_fans_finds_disjoint_group_not_callcenter():
    fans, diag = GF.detect_fans(_fan_df(), min_calls=30, min_group=4, min_disjoint=0.85)
    assert fans == {f"fan{c}" for c in range(5)}
    assert "callcenter" not in fans
    assert diag["candidates"] >= 5 and diag["capped"] is False


def test_detect_fans_empty_without_required_columns():
    fans, diag = GF.detect_fans(pd.DataFrame({"caller": ["a"]}))
    assert fans == set() and diag["candidates"] == 0


def test_validate_against_go_reports_divergence():
    df = _fan_df()
    fans, diag = GF.detect_fans(df)
    v = GF.validate_against_go(df, fans, diag)
    assert v["available"] is True
    assert v["networkx_fans"] == 5
    assert v["go_fans"] == 0  # фикстура: r_fan_member всюду 0
    assert v["only_networkx"] == 5 and v["agree"] == 0


def test_validate_against_go_full_agreement():
    df = _fan_df()
    df.loc[df["caller"].str.startswith("fan"), "r_fan_member"] = 1.0
    fans, diag = GF.detect_fans(df)
    v = GF.validate_against_go(df, fans, diag)
    assert v["agree"] == 5 and v["only_go"] == 0 and v["only_networkx"] == 0
    assert v["agreement_rate"] == 1.0


def test_graph_summary_on_empty_graph():
    import networkx as nx

    assert GF.graph_summary(nx.MultiDiGraph()) == {"nodes": 0, "edges": 0}


def test_analyze_end_to_end():
    r = GF.analyze(_fan_df())
    assert r["available"] is True
    assert r["summary"]["nodes"] > 0
    assert r["summary"]["components"] >= 2  # 5 непересекающихся вееров + компонента колл-центра
    assert r["fan_validation"]["networkx_fans"] == 5


def test_analyze_unavailable_without_caller_callee():
    r = GF.analyze(pd.DataFrame({"label": [0, 1]}))
    assert r["available"] is False and "reason" in r


def test_analyze_never_raises_on_garbage_input():
    # DataFrame с колонками, но неожиданными типами — анализ вспомогательный, не должен ронять обучение
    df = pd.DataFrame({"caller": [None, None], "callee": [None, None]})
    r = GF.analyze(df)
    assert r["available"] is False
