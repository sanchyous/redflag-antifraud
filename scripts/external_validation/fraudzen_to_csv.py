#!/usr/bin/env python3
"""Конвертирует одну сценарную выгрузку FraudZen (CDR, txt, пробел-разделённый; CC BY 4.0, DOI
10.57745/TAV6PQ, см. docs/external-validation.md) в CSV формата internal/telecom/ingest:
call_id,caller,callee,started_at,duration_sec,label.

Оставляет только голосовые типы (MOC/MTC/I-MOC/I-MTC) — DATA и MO-SMS исключены. label=1, если
src_number (звонящий) входит в список известных SIMbox-мошенников (fraudulentUsers.txt) — метка
ставится по звонящему, как и в нашей синтетике (fraud — свойство актёра, а не конкретного вызова).

Использование (после распаковки архива датасета):
    python fraudzen_to_csv.py \
        FraudZen_Cdrs/all_naive/all_naive_12%_200sims/Op_1_CDRTrace.txt \
        FraudZen_Cdrs/all_naive/all_naive_12%_200sims/fraudulentUsers.txt \
        out.csv \
        FraudZen_Cdrs/all_naive/all_naive_12%_200sims/International_CDRTrace.txt
Затем: go run ./cmd/export -numplan <справочник> -input out.csv -out <каталог датасета>
"""

import csv
import sys
from pathlib import Path

VOICE_TYPES = {"MOC", "MTC", "I-MOC", "I-MTC"}


def fix_ts(raw: str) -> str:
    # "17-3-2021 0:3:15" -> "2021-03-17 00:03:15"
    date, time = raw.split(" ")
    d, m, y = date.split("-")
    h, mi, s = time.split(":")
    return f"{y}-{int(m):02d}-{int(d):02d} {int(h):02d}:{int(mi):02d}:{int(s):02d}"


def main():
    trace_path = Path(sys.argv[1])
    fraud_path = Path(sys.argv[2])
    out_path = Path(sys.argv[3])
    intl_path = Path(sys.argv[4]) if len(sys.argv) > 4 else None

    fraud_users = {
        ln.strip()
        for ln in fraud_path.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    }
    print(f"мошеннических номеров: {len(fraud_users)}", file=sys.stderr)

    n_total = n_voice = n_fraud = 0
    with out_path.open("w", newline="", encoding="utf-8") as out:
        w = csv.writer(out)
        w.writerow(
            ["call_id", "caller", "callee", "started_at", "duration_sec", "label"]
        )

        def process(path, seq_prefix):
            nonlocal n_total, n_voice, n_fraud
            with path.open(encoding="utf-8") as f:
                f.readline()  # пропускаем заголовок: timestamp CDR_type src_number ... dst_number ... duration size
                for i, line in enumerate(f):
                    n_total += 1
                    parts = line.split()
                    if len(parts) < 11:
                        continue
                    (
                        date,
                        time,
                        cdr_type,
                        src,
                        _src_imei,
                        _c1,
                        _c2,
                        dst,
                        _dst_imei,
                        _c3,
                        _c4,
                    ) = parts[:11]
                    duration = parts[11] if len(parts) > 11 else "0"
                    if cdr_type not in VOICE_TYPES:
                        continue
                    n_voice += 1
                    label = 1 if src in fraud_users else 0
                    n_fraud += label
                    w.writerow(
                        [
                            f"{seq_prefix}-{i}",
                            src,
                            dst,
                            fix_ts(f"{date} {time}"),
                            duration,
                            label,
                        ]
                    )

        process(trace_path, "op1")
        if intl_path and intl_path.exists():
            process(intl_path, "intl")

    print(
        f"строк всего: {n_total}, голосовых: {n_voice}, из них мошеннических (по звонящему): {n_fraud}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
