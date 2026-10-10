#!/usr/bin/env python3
"""Демонстрация и смоук-тест сервиса скоринга вызовов.

    python3 scripts/demo.py --url http://192.168.10.200:8000 [--api-key KEY] [--fan] [--graph]

Гоняет ключевые сценарии, печатает решение и главные причины, а в конце сверяет жёсткие
ожидания (скорая не блокируется, подмена не проходит как allow, кампания обзвона доходит до block,
колл-центр и обычные абоненты не блокируются). Код возврата 1, если хоть одно ожидание нарушено:
скрипт можно запускать после каждого деплоя. Только стандартная библиотека.

--graph засевает экран «Граф связей» на живом стенде реалистичными данными сразу по всем четырём
детекторам (веер, карусель, SIM-box, цепочка переадресации) и клону SIM — не трюк в обход API, а те
же вызовы, что и в бою, через /v1/calls/score; ждёт один пересчёт графа (~40 с) и проверяет, что
все пять действительно нашлись.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

# Коды мобильных операторов из разных регионов РФ: обзвон по ним даёт «охват регионов».
DEF_CODES = ("900 901 902 903 904 905 906 908 909 910 911 912 913 914 915 916 917 918 919 920 921 922 923 "
             "924 925 926 927 928 929 930 931 932 933 934 936 937 938 950 951 952 953 960 961 962 963 964 "
             "965 966 967 968 969 977 978 980 981 982 983 984 985 987 988 989 991 992 993 994 995 996 997 999").split()


class Client:
    def __init__(self, base: str, api_key: str = ""):
        self.base, self.key = base.rstrip("/"), api_key

    def score(self, call: dict) -> dict:
        req = urllib.request.Request(self.base + "/v1/calls/score", data=json.dumps(call).encode(),
                                     headers={"Content-Type": "application/json", **({"X-API-Key": self.key} if self.key else {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            return {"error": e.code, "body": e.read().decode()[:200]}


def mobile(rng: random.Random, code: str | None = None) -> str:
    return f"+7{code or rng.choice(DEF_CODES)}{rng.randrange(10_000_000):07d}"


def iso(t: datetime) -> str:
    return t.isoformat(timespec="seconds")


class Report:
    def __init__(self):
        self.rows, self.failed = [], 0

    def expect(self, name: str, ok: bool, detail: str):
        self.rows.append((name, ok, detail))
        if not ok:
            self.failed += 1
        print(f"  {'✓' if ok else '✗ ОЖИДАНИЕ НАРУШЕНО'} {name}: {detail}")


def show(title: str, r: dict, n: int = 3):
    print(f"\n■ {title}")
    if "error" in r:
        print("  ошибка:", r)
        return
    extra = []
    if r.get("rule_floor"):
        extra.append("пол-правило")
    if r.get("safe_class"):
        extra.append(f"защитный класс: {r['safe_class']}")
    if r.get("block_suppressed"):
        extra.append("block отменён защитой")
    print(f"  решение: {r['decision'].upper()}  стадия: {r.get('stage')}  score: {r['score']}  "
          f"сигналы: {r.get('signals') or '-'}  {' | '.join(extra)}")
    print(f"  {r['caller'].get('masked')} → {r['callee'].get('masked')}  "
          f"({r['caller'].get('region') or '?'} → {r['callee'].get('region') or '?'})")
    for x in r.get("reasons", [])[:n]:
        print(f"    {'▲' if x['effect'] == 'raises' else '▼'} {x['text']}  (вклад {x['contribution']:+.2f})")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--api-key", default="")
    ap.add_argument("--fan", action="store_true", help="сценарий веера (ждёт ~40 с пересчёта графа)")
    ap.add_argument("--graph", action="store_true", help="засеять все 4 графовых детектора + клон SIM (ждёт ~40 с)")
    ap.add_argument("--seed", type=int, default=int(time.time()))
    a = ap.parse_args()
    rng, api, rep = random.Random(a.seed), Client(a.url, a.api_key), Report()
    uid = f"{a.seed}"
    now = datetime.now(timezone(timedelta(hours=3))).replace(microsecond=0)
    print(f"Сервис: {a.url}  seed={a.seed}")

    # 1. Пример из ТЗ
    tz = api.score({"call_id": f"tz-{uid}", "caller": "+7 495 ***-**-12", "callee": "+7 916 ***-**-83",
                    "started_at": iso(now), "duration_sec": 6, "src_country": "DE"})
    show("Пример из ТЗ: +7 495 ***-**-12 → +7 916 ***-**-83, 6 с, вход из-за рубежа", tz)
    rep.expect("пример из ТЗ не проходит как allow", tz.get("decision") in ("review", "block"), str(tz.get("decision")))

    # 2. Экстренные службы
    em_ok = True
    for i, callee in enumerate(["103", "112", "*112#", "0103"]):
        r = api.score({"call_id": f"em{i}-{uid}", "caller": mobile(rng), "callee": callee, "src_country": "DE", "duration_sec": 2})
        em_ok &= r.get("decision") == "allow" and r.get("safe_class") == "emergency"
    show("Скорая (103, 112, *112#, 0103) при подозрительных признаках источника",
         api.score({"call_id": f"emx-{uid}", "caller": "+7 495 123-45-67", "callee": "103", "src_country": "DE", "duration_sec": 2}))
    rep.expect("экстренные вызовы всегда allow", em_ok, "4 из 4" if em_ok else "есть нарушение")

    # 3. Обычный абонент
    ordinary = api.score({"call_id": f"ord-{uid}", "caller": mobile(rng, "916"), "callee": mobile(rng, "495"), "started_at": iso(now), "duration_sec": 240})
    show("Обычный разговор на 4 минуты", ordinary)
    rep.expect("обычный звонок — allow", ordinary.get("decision") == "allow", str(ordinary.get("decision")))

    # 4. Кампания обзвона с подменённого номера: от первого вызова до блокировки
    spoof = mobile(rng)
    first_review = first_block = None
    last = {}
    t = now - timedelta(hours=3)
    for i in range(120):
        t += timedelta(seconds=rng.randint(40, 110))
        last = api.score({"call_id": f"camp-{uid}-{i}", "caller": spoof, "callee": mobile(rng), "started_at": iso(t),
                          "duration_sec": rng.choice([0, 0, 0, 3, 4, 5]), "src_country": "CY", "conn_type": "international"})
        if first_review is None and last.get("decision") in ("review", "block"):
            first_review = i + 1
        if first_block is None and last.get("decision") == "block":
            first_block = i + 1
    show(f"Кампания обзвона (120 вызовов за 3 часа), итог на последнем вызове: review с {first_review}-го, block с {first_block}-го", last, 4)
    rep.expect("кампания обзвона доходит до block", first_block is not None, f"первый block на вызове №{first_block}")

    # 5. Робозвонок: одна SIM, машинная регулярность, обзвон регионов
    robo = mobile(rng)
    t = now - timedelta(hours=2)
    first_block_r, last = None, {}
    for i in range(90):
        t += timedelta(seconds=30)
        last = api.score({"call_id": f"robo-{uid}-{i}", "caller": robo, "callee": mobile(rng), "started_at": iso(t),
                          "duration_sec": 0 if rng.random() < 0.85 else rng.randint(1, 5), "src_country": "RU", "conn_type": "mobile"})
        if first_block_r is None and last.get("decision") == "block":
            first_block_r = i + 1
    show(f"Робозвонок (90 вызовов ровно раз в 30 с), block с {first_block_r}-го", last, 4)
    rep.expect("робозвонок доходит до block", first_block_r is not None, f"первый block на вызове №{first_block_r}")

    # 6. Легитимный колл-центр: много уникальных адресатов, но разговоры содержательные — не блокировать
    cc = mobile(rng, "495")
    pool = [mobile(rng, "916") for _ in range(40)]
    t = now - timedelta(hours=3)
    cc_blocked = 0
    for i in range(100):
        t += timedelta(seconds=int(rng.expovariate(1 / 90)) + 5)
        r = api.score({"call_id": f"cc-{uid}-{i}", "caller": cc, "callee": rng.choice(pool), "started_at": iso(t),
                       "duration_sec": rng.choice([0, 0, 45, 60, 80, 120, 200]), "src_country": "RU", "conn_type": "fixed"})
        cc_blocked += r.get("decision") == "block"
    show("Колл-центр (100 вызовов общему пулу из 40 клиентов), итог на последнем вызове", r, 3)
    rep.expect("колл-центр не блокируется", cc_blocked == 0, f"блокировок: {cc_blocked} из 100")

    # 7. Повторная доставка
    same = {"call_id": f"dup2-{uid}", "caller": mobile(rng), "callee": mobile(rng), "duration_sec": 30}
    api.score(dict(same))
    again = api.score(dict(same))
    rep.expect("повторная доставка распознаётся", again.get("duplicate") is True, f"duplicate={again.get('duplicate')}")

    # 8. Веер (необязательно: нужен пересчёт графа)
    if a.fan:
        base = int(mobile(rng, "911")[2:])
        t = now - timedelta(hours=1)
        for i in range(40):
            t += timedelta(seconds=60)
            for k in range(6):
                api.score({"call_id": f"fan-{uid}-{i}-{k}", "caller": f"+7{base + k:010d}", "callee": mobile(rng), "started_at": iso(t),
                           "duration_sec": rng.choice([0, 3, 4, 5]), "src_country": "RU", "conn_type": "mobile"})
        print("\n… жду пересчёта графа связей (~40 с)")
        time.sleep(40)
        r = api.score({"call_id": f"fan-probe-{uid}", "caller": f"+7{base + 2:010d}", "callee": mobile(rng), "started_at": iso(t + timedelta(seconds=60)), "duration_sec": 3,
                       "src_country": "RU", "conn_type": "mobile"})
        show("Веер: 6 подряд идущих номеров, общий шаблон, непересекающиеся списки", r, 4)
        rep.expect("веер найден графом", "fan" in (r.get("signals") or []), f"сигналы: {r.get('signals')}")

    # 9. Все четыре графовых детектора + клон SIM разом (--graph): чтобы на живом стенде (панель,
    # /v1/graph/*) сразу было что показать, а не только пустые подсказки «такого паттерна пока нет».
    if a.graph:
        print("\n--- Графовые детекторы (--graph) ---")

        # Веер (если --fan не передан отдельно)
        fan_base = int(mobile(rng, "911")[2:])
        t = now - timedelta(hours=1)
        for i in range(40):
            t += timedelta(seconds=60)
            for k in range(6):
                api.score({"call_id": f"gfan-{uid}-{i}-{k}", "caller": f"+7{fan_base + k:010d}", "callee": mobile(rng),
                           "started_at": iso(t), "duration_sec": rng.choice([0, 3, 4, 5]), "src_country": "RU", "conn_type": "mobile"})

        # Карусель: закрытая группа из 6 номеров звонит только друг другу
        group = [mobile(rng, "933") for _ in range(6)]
        t = now - timedelta(hours=18)
        for i in range(110):
            for caller in group:
                callee = rng.choice([g for g in group if g != caller])
                t += timedelta(seconds=rng.randint(3, 9))
                api.score({"call_id": f"car-{uid}-{i}-{group.index(caller)}", "caller": caller, "callee": callee,
                           "started_at": iso(t), "duration_sec": rng.randint(8, 45), "src_country": "RU", "conn_type": "mobile"})

        # SIM-box: несколько SIM работают только на исходящие, каждый получатель — новый
        simbox_nums = []
        for s in range(3):
            sim = mobile(rng, "966")
            simbox_nums.append(sim)
            t = now - timedelta(hours=16)
            for i in range(60):
                t += timedelta(seconds=rng.randint(200, 500))
                api.score({"call_id": f"sbx-{uid}-{s}-{i}", "caller": sim, "callee": mobile(rng),
                           "started_at": iso(t), "duration_sec": rng.randint(15, 40), "src_country": "RU", "conn_type": "mobile"})

        # Цепочка переадресации: B → C → D → E (3 перехода)
        nodes = [mobile(rng, "944") for _ in range(4)]
        t = now - timedelta(minutes=30)
        for i in range(3):
            t += timedelta(seconds=20)
            api.score({"call_id": f"chain-{uid}-{i}", "caller": mobile(rng), "callee": nodes[i], "started_at": iso(t),
                       "duration_sec": rng.randint(5, 30), "direction": "forwarded", "forward_to": nodes[i + 1],
                       "src_country": "RU", "conn_type": "mobile"})

        # Клон SIM: один номер, несколько разных IMSI
        clone_num = mobile(rng, "955")
        t = now - timedelta(hours=2)
        for i in range(5):
            t += timedelta(minutes=rng.randint(5, 40))
            api.score({"call_id": f"clone-{uid}-{i}", "caller": clone_num, "callee": mobile(rng), "started_at": iso(t),
                       "duration_sec": rng.randint(10, 60), "imsi": f"250011234{i:06d}", "src_country": "RU", "conn_type": "mobile"})

        print("\n… жду пересчёта графовых индексов (~40 с)")
        time.sleep(40)

        r_car = api.score({"call_id": f"car-probe-{uid}", "caller": group[0], "callee": group[1], "started_at": iso(now),
                            "duration_sec": 20, "src_country": "RU", "conn_type": "mobile"})
        show("Карусель: 6 номеров звонят только друг другу", r_car, 4)
        rep.expect("карусель найдена графом", "carousel" in (r_car.get("signals") or []), f"сигналы: {r_car.get('signals')}")

        r_sbx = api.score({"call_id": f"sbx-probe-{uid}", "caller": simbox_nums[0], "callee": mobile(rng), "started_at": iso(now),
                            "duration_sec": 20, "src_country": "RU", "conn_type": "mobile"})
        show("SIM-box: только исходящие, каждый получатель новый", r_sbx, 4)
        rep.expect("SIM-box найден графом", "sim_box" in (r_sbx.get("signals") or []), f"сигналы: {r_sbx.get('signals')}")

        r_chain = api.score({"call_id": f"chain-probe-{uid}", "caller": mobile(rng), "callee": nodes[0], "started_at": iso(now),
                              "duration_sec": 10, "direction": "forwarded", "forward_to": nodes[1], "src_country": "RU", "conn_type": "mobile"})
        show("Цепочка переадресации: B → C → D → E", r_chain, 4)
        rep.expect("цепочка найдена графом", "forward_chain" in (r_chain.get("signals") or []), f"сигналы: {r_chain.get('signals')}")

        r_clone = api.score({"call_id": f"clone-probe-{uid}", "caller": clone_num, "callee": mobile(rng), "started_at": iso(now),
                              "duration_sec": 10, "imsi": "2500199999999", "src_country": "RU", "conn_type": "mobile"})
        show("Клон SIM: один номер, несколько IMSI", r_clone, 4)
        rep.expect("клон SIM найден", "sim_clone" in (r_clone.get("signals") or []), f"сигналы: {r_clone.get('signals')}")

    print(f"\n{'=' * 60}\nИтог: {len(rep.rows) - rep.failed} из {len(rep.rows)} ожиданий выполнено")
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())
