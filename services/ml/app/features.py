"""Контракт признаков с Go-ядром.

Список и порядок признаков задаёт Go (internal/features): здесь они читаются из meta.json модели,
а не хардкодятся, чтобы рассинхрон обнаруживался при загрузке. Знак монотонного ограничения —
здравый смысл предметной области: рост признака не может снижать риск (кроме длительности разговора).
"""

from __future__ import annotations

# Признаки, у которых рост значения ОБЯЗАН повышать риск (monotone +1).
# Длительность разговора — смягчающий фактор (monotone -1). Остальные — без ограничения.
MONOTONE_INCREASING = {
    "out_calls_1h",
    "out_calls_24h",
    "out_peers_1h",
    "out_peers_24h",
    "out_novelty",
    "out_regions_24h",
    "out_region_entropy",
    "out_short_share",
    "out_unanswered_share",
    "out_gap_robot",
    "call_short",
    "call_hangup_1s",
    "call_unanswered",
    "call_night",
    "foreign_ingress",
    "spoof",
    "caller_unallocated",
    "caller_invalid",
    "operator_mismatch",
    "conn_international",
    "fan_member",
    "fan_size",
    "subscriber_numbers",
    "imsi_count",
    "chain_member",
    "chain_depth",
    "simbox_member",
    "carousel_member",
}
MONOTONE_DECREASING = {"call_duration"}


def monotone_constraints(feature_names: list[str]) -> list[int]:
    """Вектор ограничений в порядке признаков для CatBoost."""
    out = []
    for name in feature_names:
        if name in MONOTONE_INCREASING:
            out.append(1)
        elif name in MONOTONE_DECREASING:
            out.append(-1)
        else:
            out.append(0)
    return out
