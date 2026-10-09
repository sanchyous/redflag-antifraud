# Наблюдаемость: логи, метрики, панель

## Панель мониторинга (`/ui/`)

Встроена в бинарь ядра (без внешних зависимостей, работает в закрытом контуре). Подробный разбор каждого
экрана — что он показывает и как им пользоваться — в [interface.md](interface.md); здесь — только то, что
касается наблюдаемости: панель берёт данные из API (`GET /v1/status`, `/v1/stats?window=&points=`,
`/v1/events`, `/v1/model`, `/v1/graph/fans|chains|simbox|carousel`, `/v1/ml/report`, `/v1/ml/service`).
Если задан `API_KEY`, страница всё равно открывается без ключа, а вот данные на ней появятся только
после того, как ключ будет введён в интерфейсе (значок справа сверху) — он хранится в `sessionStorage`
вкладки и уходит только в заголовке `X-API-Key` запросов к тому же серверу.

## Логи

Формат: `json` (продакшен) или `pretty` (консоль): `20:04:48.317 INFO  api        decision call_id=… decision=review …`.
Правила: сообщение — короткий идентификатор события в snake_case; всё переменное — в полях; номера — только маскированные;
у каждой записи запроса есть `request_id`, у каждой подсистемы — `component`.

| Событие | Уровень | Когда |
|---|---|---|
| `decision` | info (allow — debug) | решение по вызову; `LOG_DECISIONS=flagged`, `all` или `off` |
| `ml_stage_ready`, `ml_model_changed` | info | ML-стадия активирована или сменилась версия модели |
| `ml_stage_disabled` | error | несовместимый контракт признаков: стадия 2 отключена |
| `ml_breaker_opened` | warn | ML недоступен, решения принимает стадия 1 |
| `ml_breaker_closed` | info | ML снова доступен |
| `fan_index_updated` | info при изменении, иначе debug | найдены новые или исчезли веера |
| `api_unprotected` | warn | `API_KEY` пуст |
| `http_request` | debug / warn (4xx) / error (5xx) | доступ к API |

Горячий путь защищён от логового шторма: одно и то же событие ограничивается `LOG_RATE_PER_SEC` в секунду (по умолчанию 200),
отброшенное считается и раз в секунду сообщается событием `log_dropped`; предупреждения и ошибки не ограничиваются.

## Метрики (`/metrics`, Prometheus)

`redflag_decisions_total{decision}`, `redflag_score_latency_seconds` (гистограмма), `redflag_ml_calls_total`, `redflag_ml_errors_total`,
`redflag_ml_skipped_total` (breaker открыт), `redflag_rule_floors_total`, `redflag_emergency_total`, `redflag_duplicates_total`,
`redflag_tracked_numbers`, `redflag_fan_groups`, `redflag_journal_*`.

### Grafana

`deploy/grafana/redflag-dashboard.json` — готовый дашборд (решения по времени, p50/p95/p99, ML-каскад,
журнал, окна/веера, ошибки и паники). Поднять Prometheus + Grafana поверх основного стенда:

```bash
docker compose -f compose.yaml -f deploy/grafana/compose.monitoring.yaml --profile monitoring up -d
```

Datasource Prometheus провижинится автоматически; дашборд — один Import в UI Grafana (Dashboards → New →
Import → загрузить JSON). Совместимо и с VictoriaMetrics вместо Prometheus (PromQL, включая
`histogram_quantile`) — см. комментарий в `compose.monitoring.yaml`.
