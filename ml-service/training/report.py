"""Отчёт об обучении и оценке (Markdown, по-русски)."""
from __future__ import annotations

from datetime import date
from pathlib import Path

LEGIT = ["regular", "heavy_user", "call_center", "bank_notify", "courier", "roamer", "foreign_caller", "corp_multi", "emergency"]
FRAUD = ["spoof_burst", "robocall", "one_ring", "fan", "sim_farm", "cold_spam"]


def _pct(a: float, b: float) -> float:
    return 100.0 * a / b if b else 0.0


def write_report(path: Path, *, meta: dict, test: dict, test_flat: dict, targets, n_train: int, n_calib: int,
                 importances: dict[str, float]) -> None:
    th = meta["thresholds"]
    L: list[str] = []
    p = L.append
    p("# Отчёт об обучении ML-модели (CatBoost)")
    p("")
    p(f"Дата: {date.today().isoformat()}. Модель: `{meta['version']}`. Пороги: review = {th['review']:.4f}, "
      f"block = {th['block']:.4f}, ворота каскада (стадия 1 → ML) = {th['gate']:.4f}.")
    p("")
    p("## Постановка")
    p(f"- обучение: {n_train} вызовов; калибровка и пороги: {n_calib}; независимая проверка: {test['n'] + test['emergency']['n']} "
      "(три разных seed генератора; номера в наборах не пересекаются)")
    p("- модель: CatBoost с монотонными ограничениями (рост признака не может снижать риск, кроме длительности разговора); "
      "ранняя остановка по отложенной части, разбитой по номерам")
    p(f"- калибровка Платта под ожидаемую долю мошенничества {meta['prevalence']:.2%}; вес легитимных при обучении {meta['legit_weight']}")
    p(f"- целевая доля ложных срабатываний: review ≤ {targets.review_fpr:.2%}, block ≤ {targets.block_fpr:.3%} легитимных вызовов")
    p(f"- block требует score ≥ порога и не менее {targets.min_signals} независимых сильных сигналов; защищённые классы не блокируются")
    p("")
    p("## Итог на независимой проверке (каскад: стадия 1 → ML)")
    p("")
    p("| Метрика | Значение |")
    p("|---|---|")
    p(f"| Вызовов (без экстренных) | {test['n']} (легитимных {test['legit']}, мошеннических {test['fraud']}) |")
    p(f"| ROC-AUC | {test['auc']:.4f} |")
    p(f"| PR-AUC | {test['pr_auc']:.4f} |")
    r, b = test["review"], test["block"]
    p(f"| review: recall / FPR | {r['recall']:.1%} / {r['fpr']:.3%} |")
    p(f"| block: recall / FPR | {b['recall']:.1%} / {b['fpr']:.4%} |")
    p(f"| block: ложных блокировок легитимных | {b['fp']} из {test['legit']} |")
    p(f"| review: ложных отметок легитимных | {r['fp']} из {test['legit']} |")
    p(f"| доля трафика, уходящая в ML | {test['ml_traffic_share']:.1%} (легитимного: {test['ml_traffic_share_legit']:.1%}) |")
    rf = test["rule_floor"]
    p(f"| поднято до review жёстким правилом (модель молчала) | легитимных {rf['legit']}, мошеннических {rf['fraud']} |")
    p("")
    fr, bl = test_flat["review"], test_flat["block"]
    p(f"Если ML применять ко всему трафику (без ворот): review recall {fr['recall']:.1%}, block recall {bl['recall']:.1%}; "
      f"ворота стоят {fr['recall'] - r['recall']:.2%} recall по review, но снимают с ML основную нагрузку.")
    p("")
    p("Точность (precision) зависит от доли мошенничества в потоке; при тех же recall и FPR:")
    p("")
    p("| Доля мошеннических вызовов | precision(review) | precision(block) |")
    p("|---|---|---|")
    from .evaluate import precision_at
    for prev in (0.001, 0.01, 0.05, 0.15):
        p(f"| {prev:.1%} | {precision_at(r['recall'], r['fpr'], prev):.1%} | {precision_at(b['recall'], b['fpr'], prev):.1%} |")
    p("")
    e = test["emergency"]
    p("## Экстренные службы")
    p("")
    p(f"Вызовов на 112/101/102/103/104 в проверке: **{e['n']}**; allow: **{e['allowed']}**; заблокировано: **{e['blocked']}**. "
      "Защитный слой стоит выше модели: блокировка скорой невозможна архитектурно.")
    p("")
    p("## Ложные срабатывания по типам легитимных абонентов")
    p("")
    p("| Тип | Вызовов | review+ | block | Доля в ML |")
    p("|---|---|---|---|---|")
    for k in LEGIT:
        if k in test["by_kind"]:
            v = test["by_kind"][k]
            p(f"| {k} | {v['n']} | {v['review']} ({_pct(v['review'], v['n']):.2f}%) | {v['block']} | {_pct(v['ml'], v['n']):.1f}% |")
    p("")
    p("## Обнаружение по типам мошенничества")
    p("")
    p("| Тип | Вызовов | review+ (доля) | block (доля) | Доля в ML |")
    p("|---|---|---|---|---|")
    for k in FRAUD:
        if k in test["by_kind"]:
            v = test["by_kind"][k]
            p(f"| {k} | {v['n']} | {_pct(v['review'], v['n']):.1f}% | {_pct(v['block'], v['n']):.1f}% | {_pct(v['ml'], v['n']):.1f}% |")
    p("")
    c = test["callers"]
    p("## Скорость реакции на номер-нарушитель")
    p("")
    p(f"- мошеннических номеров: {c['fraud_callers']}; review получили {c['reviewed']} ({_pct(c['reviewed'], c['fraud_callers']):.1f}%); "
      f"block получили {c['blocked']} ({_pct(c['blocked'], c['fraud_callers']):.1f}%)")
    p(f"- медиана вызовов до первой отметки review: {c['median_calls_to_review']}; до первого block: {c['median_calls_to_block']} "
      "(прошедшие до реакции вызовы — цена холодного старта)")
    p("")
    p("## Важность признаков (CatBoost)")
    p("")
    p("| Признак | Важность |")
    p("|---|---|")
    for name, val in sorted(importances.items(), key=lambda kv: -kv[1]):
        p(f"| {name} | {val:.2f} |")
    p("")
    p("## Замечания")
    p("- данные синтетические (генератор `internal/synth`); на реальных данных цифры будут другими")
    p("- метрики посчитаны на наборе, не участвовавшем ни в обучении, ни в подборе порогов и ворот")
    p("- доля трафика в ML определяется составом потока: в синтетике трудных легитимных абонентов (колл-центры, банки, "
      "тяжёлые пользователи) намного больше, чем в реальной сети, поэтому 40% здесь — верхняя оценка; обычные абоненты "
      "уходят в ML лишь тогда, когда стадия 1 их отметила")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")
