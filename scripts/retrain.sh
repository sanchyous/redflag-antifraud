#!/usr/bin/env bash
# Полное переобучение: две стадии каскада за один прогон.
#
#   scripts/retrain.sh /path/to/numplan [/path/to/labeled.csv|jsonl]
#
# 1) выгрузка признаков (синтетика или размеченный файл организаторов)
# 2) обучение линейной стадии 1 (ограничения знаков, объяснимая) → models/stage1.json
# 3) повторная выгрузка: оценка s1 и сильные сигналы считаются уже обученной стадией 1
# 4) обучение ML-стадии (CatBoost): пороги, калибровка, ворота под обученную стадию 1 → models/current
# Стадии обучаются в таком порядке, потому что ворота ML подбираются по оценке именно обученной
# стадии 1; выкатывать обе модели нужно вместе (сначала ML, затем стадию 1).
set -euo pipefail
NUMPLAN="${1:?укажите каталог со справочником нумерации}"
INPUT="${2:-}"
PY="${PYTHON:-python3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/ml-service/models}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

EXPORT_ARGS=(-numplan "$NUMPLAN")
[ -n "$INPUT" ] && EXPORT_ARGS+=(-input "$INPUT")

cd "$ROOT"
echo "== 1/4 выгрузка признаков (экспертная стадия 1)"
go run ./cmd/export "${EXPORT_ARGS[@]}" -out "$WORK/pass1"
cd ml-service
echo "== 2/4 обучение линейной стадии 1"
mkdir -p "$OUT"
$PY -m training.stage1 --data "$WORK/pass1" --out "$OUT/stage1.json"
cd "$ROOT"
echo "== 3/4 повторная выгрузка с обученной стадией 1"
go run ./cmd/export "${EXPORT_ARGS[@]}" -model "$OUT/stage1.json" -out "$WORK/pass2"
cd ml-service
echo "== 4/4 обучение ML-стадии (CatBoost)"
$PY -m training.train --data "$WORK/pass2" --out "$OUT/current" --report "$OUT/report.md"
echo
echo "Готово: $OUT/stage1.json (MODEL_FILE ядра), $OUT/current (каталог модели ML), $OUT/report.md"
