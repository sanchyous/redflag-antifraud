from app.features import MONOTONE_DECREASING, MONOTONE_INCREASING, monotone_constraints
from tests.conftest import FEATURES


def test_every_feature_has_defined_direction():
    cons = monotone_constraints(FEATURES)
    assert len(cons) == len(FEATURES)
    assert cons[FEATURES.index("call_duration")] == -1
    assert cons[FEATURES.index("spoof")] == 1
    assert cons[FEATURES.index("in_calls_1h")] == 0  # нагрузка на получателя — не признак нарушителя


def test_monotone_sets_reference_known_features():
    unknown = (MONOTONE_INCREASING | MONOTONE_DECREASING) - set(FEATURES)
    assert not unknown, f"ограничения для несуществующих признаков: {unknown}"
    assert not (MONOTONE_INCREASING & MONOTONE_DECREASING)


def test_matches_go_feature_list_if_available():
    """Если рядом лежит исходник Go — имена признаков должны совпадать (защита от рассинхрона)."""
    import re
    from pathlib import Path

    src = Path(__file__).resolve().parents[3] / "internal" / "detection" / "features" / "features.go"
    if not src.exists():
        return
    text = src.read_text(encoding="utf-8")
    block = text[text.index("var Names = [N]string{") :]
    block = block[: block.index("}\n")]
    names = re.findall(r'"([a-z0-9_]+)"', block)
    assert names == FEATURES
