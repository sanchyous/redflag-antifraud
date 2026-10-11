# Содержание

* [RedFlag — обзор и быстрый старт](README.md)

## Документация

* [Обзор документации](docs/README.md)
* [Архитектура](docs/architecture.md)
* [Интерфейс панели](docs/interface.md)
* [Машинное обучение](docs/ml.md)
* [Безопасность: блокировка скорой и цена ошибки](docs/safety.md)
* [Трассировка ТЗ → код](docs/case-compliance.md)
* [Внешняя валидация (FraudZen)](docs/external-validation.md)
* [Теория (черновые заметки)](docs/theory.md)
* [Производительность](docs/performance.md)
* [Наблюдаемость](docs/observability.md)
* [Runbook](docs/runbook.md)

## Архитектурные решения (ADR)

* [Журнал ADR — обзор](docs/adr/README.md)
* [0001 — Ядро на Go, без Python](docs/adr/0001-go-core.md)
* [0002 — Аддитивная логит-модель + правила](docs/adr/0002-additive-logit-model.md)
* [0003 — Транзакционный домен заменяется доменом звонков](docs/adr/0003-calls-domain.md)
* [0004 — Решение трёхуровневое, автоблок — отдельная политика](docs/adr/0004-three-level-verdict.md)
* [0005 — Персональные данные](docs/adr/0005-personal-data.md)
* [0006 — Каталог документации вне git](docs/adr/0006-docs-location.md)
* [0007 — Регион = субъект РФ](docs/adr/0007-region-normalization.md)
* [0008 — Реестр — данные, а не код](docs/adr/0008-registry-as-data.md)
* [0009 — Окна по номерам в памяти процесса](docs/adr/0009-in-memory-windows.md)
* [0010 — ML — отдельный Python-сервис](docs/adr/0010-python-ml-service.md)
* [0011 — Регуляризация и коллинеарность](docs/adr/0011-regularization.md)
* [0012 — Жёсткий пол вердикта для подмены номера](docs/adr/0012-hard-signal-floor.md)
* [0013 — Роумер в синтетике как домашний абонент](docs/adr/0013-synthetic-roamer.md)
* [0014 — ML-сервис — необязательный профиль compose](docs/adr/0014-ml-compose-profile.md)
* [0015 — Ворота каскада и доля ML-трафика](docs/adr/0015-cascade-gate.md)
* [0016 — Линейная стадия 1 обучается на данных](docs/adr/0016-trained-stage1.md)
* [0017 — Специализированный кодировщик ответа](docs/adr/0017-fast-response-encoding.md)
* [0018 — Офлайн-графовый анализ (NetworkX) в обучении](docs/adr/0018-networkx-graph-analysis.md)
* [0019 — Четыре графовых детектора по датасету кейса](docs/adr/0019-case-dataset-detectors.md)

## Прочее

* [История изменений](CHANGELOG.md)
* [Участие в разработке](CONTRIBUTING.md)
