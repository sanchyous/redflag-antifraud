import numpy as np

from tests.conftest import make_split
from training import evaluate as E


def test_popcount():
    assert list(E.popcount(np.array([0, 1, 3, 5, 255, 1 << 10]))) == [0, 1, 2, 2, 8, 1]


def test_quantile_above_lets_through_at_most_allowed():
    v = np.array([0.1, 0.5, 0.2, 0.9, 0.3], dtype=np.float32)
    for allowed in range(0, 5):
        q = E.quantile_above(v.copy(), allowed)
        assert (v >= np.float32(q)).sum() <= allowed
    assert E.quantile_above(v, 5) == 0.0 and E.quantile_above(np.array([]), 0) == 0.0
    # ничьи на границе не должны проходить порог
    ties = np.array([0.5, 0.5, 0.5, 0.1], dtype=np.float32)
    assert (ties >= np.float32(E.quantile_above(ties, 1))).sum() <= 1


def test_fit_thresholds_respects_targets():
    df = make_split(6000, 7, with_emergency=False)
    rng = np.random.default_rng(0)
    scores = np.where(df["label"] == 1, rng.beta(6, 2, len(df)), rng.beta(1, 30, len(df)))
    t = E.Targets(review_fpr=0.01, block_fpr=0.001)
    review, block = E.fit_thresholds(scores, df, t)
    assert 0 < review <= block <= 1
    v = E.verdicts(scores, df, review, block, t.min_signals)
    legit = df["label"].to_numpy() == 0
    assert (v[legit] >= 1).mean() <= t.review_fpr + 1e-9
    assert (v[legit] == 2).mean() <= t.block_fpr + 1e-9


def test_verdict_invariants():
    df = make_split(3000, 11)
    rng = np.random.default_rng(1)
    for _ in range(20):
        scores = rng.random(len(df))
        review, block = sorted(rng.random(2))
        review = max(review, 0.01)
        v = E.verdicts(scores, df, review, max(block, review))
        cls = df["class"].to_numpy()
        assert (v[cls == 3] == 0).all(), "экстренные всегда allow"
        assert (v[cls != 0] < 2).all(), "защищённые классы не блокируются"
        strong = E.popcount(df["signals"].to_numpy()) >= 2
        assert (v[v == 2].size == 0) or strong[v == 2].all(), "block только при сильных сигналах"


def test_hard_signal_floor_in_verdicts():
    df = make_split(2000, 21)
    df.loc[df.index[:50], "signals"] = E.HARD_SIGNALS_MASK
    df.loc[df.index[:50], "class"] = 0
    scores = np.full(len(df), 1e-6)
    v = E.verdicts(scores, df, review=0.3, block=0.9)
    first = df.index[:50]
    assert (v[first][df["class"].to_numpy()[first] == 0] >= 1).all(), "жёсткий сигнал даёт пол review при любом score"
    assert (v[first] < 2).all(), "пол не превращается в block"
    em = df.copy()
    em["class"] = 3
    assert (E.verdicts(scores, em, 0.3, 0.9) == 0).all(), "экстренные важнее пола"
    volume = df.copy()
    volume["signals"] = 8  # burst: объёмный сигнал пола не даёт
    assert (E.verdicts(scores, volume, 0.3, 0.9)[df["class"].to_numpy() != 3] == 0).all()


def test_fit_thresholds_accounts_for_floor_budget():
    df = make_split(8000, 22, with_emergency=False)
    legit = df["label"].to_numpy() == 0
    rng = np.random.default_rng(3)
    df.loc[df.index[legit][:40], "signals"] = E.HARD_SIGNALS_MASK  # легитимные с жёстким сигналом
    scores = np.where(df["label"] == 1, rng.beta(6, 2, len(df)), rng.beta(1, 30, len(df)))
    t = E.Targets(review_fpr=0.01)
    review, block = E.fit_thresholds(scores, df, t)
    v = E.verdicts(scores, df, review, block)
    fpr = (v[legit] >= 1).mean()
    assert fpr <= t.review_fpr + 1e-9, f"с учётом пола FPR {fpr:.4f} превысил цель"


def test_gate_not_above_stage1_review_and_reaches_most_fraud():
    df = make_split(6000, 5, with_emergency=False)
    t = E.Targets(gate_recall=0.99)
    gate = E.fit_gate(df, 0.15, t)
    assert 0 < gate <= 0.15
    reach = E.reachable(df, gate)
    fraud = df["label"].to_numpy() == 1
    assert reach[fraud].mean() >= 0.985
    assert reach[~fraud].mean() < 0.5, "ворота должны снимать с ML основную часть легитимного трафика"


def test_gate_respects_ml_share_cap():
    df = make_split(6000, 9, with_emergency=False)
    loose = E.fit_gate(df, 0.15, E.Targets(gate_recall=0.999, max_ml_share=1.0))
    capped = E.fit_gate(df, 0.15, E.Targets(gate_recall=0.999, max_ml_share=0.25))
    assert capped >= loose
    share = E.reachable(df, capped).mean()
    assert share <= 0.25 + 1e-6 or capped == 0.15, "предел нагрузки ML должен соблюдаться, если он достижим"
    # недостижимый предел (сильные сигналы сами дают больше) → верхняя граница, а не ошибка
    assert E.fit_gate(df, 0.15, E.Targets(max_ml_share=0.0)) == 0.15


def test_evaluate_shape_and_emergency():
    df = make_split(3000, 3)
    rng = np.random.default_rng(2)
    scores = np.where(df["label"] == 1, rng.beta(6, 2, len(df)), rng.beta(1, 30, len(df)))
    m = E.evaluate(scores, df, review=0.3, block=0.9, gate=0.05)
    assert (
        m["emergency"]["n"] > 0 and m["emergency"]["blocked"] == 0 and m["emergency"]["allowed"] == m["emergency"]["n"]
    )
    assert m["review"]["tp"] + m["review"]["fn"] == m["fraud"]
    assert set(m["by_kind"]) >= {"regular", "call_center"}
    assert 0 <= m["ml_traffic_share"] <= 1
    assert m["callers"]["fraud_callers"] > 0
    flat = E.evaluate(scores, df, review=0.3, block=0.9, gate=0.05, cascade=False)
    assert flat["review"]["recall"] >= m["review"]["recall"] - 1e-12  # ворота не могут повысить recall


def test_precision_at():
    assert abs(E.precision_at(0.8, 0.01, 0.01) - 0.008 / (0.008 + 0.0099)) < 1e-12
    assert E.precision_at(0, 0, 0.1) == 0.0
