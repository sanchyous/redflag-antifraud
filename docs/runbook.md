# Эксплуатация

## Стенд

Сервер `192.168.10.200` (ВМ Proxmox), доступ: `ssh redflag` (порт 8443, ключ). Стек compose: `app` (ядро, :8000), `ml` (профиль `ml`),
`postgres`. Секреты — только в `~/redflag/.env` на сервере (в git их нет).

## Деплой

Автоматически на каждый push в `main`: self-hosted раннер на ВМ делает `docker compose up -d --build`. Если код сервиса не изменился,
образ идентичен и контейнер не пересоздаётся — это нормально. Ручная выкатка (если раннер недоступен) — из рабочей папки раннера:

```bash
cd ~/actions-runner/_work/redflag-antifraud/redflag-antifraud
docker compose --env-file /home/deploy/redflag/.env up -d --build
```

Для сборки образов нужен доступ ВМ к Docker Hub, PyPI и proxy.golang.org.

## Модели

Переобучение: `make retrain NUMPLAN=/путь/к/справочнику [DATA=размеченный.csv]` → `services/ml/models/stage1.json` и `services/ml/models/current/`.
Выкатка — **сначала ML, затем стадия 1** (ворота ML подобраны под конкретную стадию 1):

```bash
rsync -a services/ml/models/current/ redflag:redflag/models/next/
ssh redflag 'cd ~/redflag/models && cp -a current current.prev && cp next/model.cbm next/meta.json current/ &&
  docker exec redflag-antifraud-ml-1 python -c "import urllib.request as u;print(u.urlopen(u.Request(\"http://127.0.0.1:8100/v1/reload\",method=\"POST\")).read())"'
rsync -a services/ml/models/stage1.json redflag:redflag/config/stage1.json
ssh redflag 'cd ~/actions-runner/_work/redflag-antifraud/redflag-antifraud &&
  docker compose --env-file /home/deploy/redflag/.env up -d --no-build app'
```

Откат ML: вернуть `current.prev` и снова `/v1/reload`.

## Проверка

```bash
make demo URL=http://192.168.10.200:8000     # ожидается «8 из 8 ожиданий выполнено»
curl -s http://192.168.10.200:8000/metrics | grep redflag_
```

## Частые ситуации

| Симптом | Причина / действие |
|---|---|
| приложение перезапускается | смотреть `docker logs redflag-antifraud-app-1`; ошибки конфигурации (справочник, модель, БД) — fail-fast на старте |
| `ml_errors` растёт, `stage=linear` | ML недоступен или медленный; breaker откроется сам, решения принимает стадия 1 |
| `ml_ready` нет в логе | ML поднялся позже ядра; ядро перечитывает описание модели раз в минуту |
| сборка падает `EOF` на registry | у ВМ нет доступа к Docker Hub / PyPI / proxy.golang.org |
| нет связи с ВМ с ноутбука | VPN-туннель перехватывает подсеть 192.168.10.0/24: правило direct для LAN |

## Переменные окружения

Полный список с комментариями — `.env.example`.
