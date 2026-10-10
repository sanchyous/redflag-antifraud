# Трассировка: пункты ТЗ кейса → код

Кейс №4 «Антифрод без прослушки» (Nexign, хакатон «Телеком будущего»). Документ — не пересказ ТЗ,
а обратная трассировка: каждый пункт материалов кейса → конкретный файл и место в коде, которое его
закрывает. Цель — чтобы проверка жюри заняла минуты, а не требовала верить на слово.

Источник пунктов — `Кейсы_Nexign_хакатон_телеком_будущего_1.pdf`, раздел 4.

## 1. «По вызову»: длительность, время суток, тип соединения, страна и оператор источника, отбой на 1-й секунде

Все пять — поля вектора признаков `internal/detection/features/features.go`:

| Требование | Признак | Источник |
|---|---|---|
| длительность | `CallDuration` | `ev.DurSec` |
| время суток | `CallNight` | `enrich.Result.Night` — `internal/detection/enrich/enrich.go:40` |
| тип соединения | `ConnInternational` | `callrec.ConnType` (`ConnMobile/ConnFixed/ConnInternational/ConnVoIP`, `internal/telecom/callrec/callrec.go:10-28`) |
| страна/оператор источника | `SrcCountry`, `SrcOperator`, `OperatorMismatch` | поля `callrec.Call` + сверка со справочником в `enrich` |
| отбой на 1-й секунде | `CallHangup1s` | флаг `callrec.FlagHangup1s`, выставляется при `длительность ≤ 1 с` у принятого вызова |

## 2. «По номеру за окно времени»: вызовов в час, уникальных собеседников, охват регионов, доля коротких, доля неотвеченных

`internal/detection/window/window.go`, тип `NumFeatures` (строки 53-64):

```go
type NumFeatures struct {
    Calls1h, Calls24h uint32
    Peers1h, Peers24h uint32  // уникальные собеседники
    Regions24h        uint16  // уникальные регионы собеседников
    RegionEntropy     float32 // энтропия распределения регионов, бит
    ShortShare        float32 // доля коротких среди принятых (24 ч)
    UnansweredShare   float32 // доля неотвеченных (24 ч)
    GapMeanSec        float32 // средний интервал между вызовами за 1 ч
    GapCV             float32 // коэффициент вариации интервалов за 1 ч
}
```

Сверх требования: `GapMeanSec`/`GapCV` — регулярность интервалов между вызовами, признак робозвонка
(используется как `OutGapRobot` в `features.go`), в ТЗ не просили, добавили по факту разбора датасета.

## 3. «По графу связей»: сколько номеров на абонента, детектор «веера»

Реализовано четыре детектора плюс привязка номеров к абоненту и клон SIM — шире минимума ТЗ.

- **Номеров на абонента / клон SIM** — `internal/detection/graph/subscribers.go` (`Subscribers.Observe`,
  максимум 64 номера на абонента) и отдельно `internal/detection/graph/idents.go` (`Idents.Observe` —
  число разных IMSI на один номер, признак клонирования SIM, `ImsiCount`).
- **Веер** — `internal/detection/graph/fan.go`. Группа номеров с одинаковым поведенческим профилем
  (`cohortOf`), ≥`MinGroup` (по умолчанию 4) участников и непересечением списков собеседников
  ≥`MinDisjoint` (0.85) считается веером. Пороги: `MinCalls=30`, `MinUnanswer=0.5`, `MaxMeanDur=15с`.
- **Цепочка переадресации** (не в минимальном ТЗ, найдена на официальном датасете кейса, сценарий S5) —
  `internal/detection/graph/chain.go`, `AnalyzeChains`; легальный узел сбора (горячая линия) исключён
  по `HubFanIn=10`.
- **SIM-box** (сценарий S3) — `internal/detection/graph/simbox.go`: только исходящие, новый собеседник
  каждый раз, обычная (не короткая) длительность — то, что веер намеренно пропускает.
- **Карусель** (сценарий S6) — `internal/detection/graph/carousel.go`: закрытая группа 5–10 номеров,
  звонящих почти исключительно друг другу.

Honest-ограничения по графовым детекторам и независимая кросс-валидация с официальным датасетом —
[ADR-0019](adr/0019-case-dataset-detectors.md).

## 4. «Обязательное требование — объяснимость»: факторы с вкладом

- Структура факторов — `internal/decision/explain/explain.go:16-22`:
  ```go
  type Reason struct {
      Factor       string  `json:"factor"`
      Value        float64 `json:"value"`
      Contribution float64 `json:"contribution"`
      Effect       string  `json:"effect"` // "raises" | "lowers"
      Text         string  `json:"text"`
  }
  ```
- Стадия 1 (линейная модель) — точные вклады по логистическим весам, не приближение.
- Стадия 2 (ML, CatBoost) — настоящий TreeSHAP, не суррогат: `services/ml/app/model.py:129`
  `self.model.get_feature_importance(Pool(X, feature_names=self.features), type="ShapValues")`.
- Каждый `Response` (API-ответ на скоринг вызова) содержит `Reasons []explain.Reason` —
  `internal/decision/engine/engine.go:47-68`.
- «Нужны факторы, иначе решение нельзя... защитить перед регулятором» — буквально реализовано:
  кнопка «Сформировать акт для надзорного органа» на каждой карточке решения формирует печатную форму
  вердикта с факторами (`web/js/act.js`, `openAct()`).

## 5. «Как выглядит результат»: карточка вызова, score, факторы с вкладом, рекомендация

`web/js/views/playground.js`, `verdictCard()` — вызов → score (полоса риска) → факторы с вкладом
(направленные полосы «вправо — повышает риск, влево — снижает») → решение (`allow`/`review`/`block`
вместо текстовых чипов мокапа ТЗ — по сути то же самое, однозначнее трёх текстовых вариантов).
Тот же компонент переиспользован в разборе любого события на панели (`web/js/views/problems.js`,
`openEvent()`).

## 6. «Как оцениваем — на закрытом наборе, акцент на долю ложных срабатываний; что если заблокируем скорую»

**Защита экстренных номеров — архитектурная, не весовая:**
- `internal/detection/protect/protect.go` — класс `Emergency` (`Classify()`, строка 124),
  `NeverBlock()` (строка 40): вердикт для защищённых классов не может подняться выше `review`
  независимо от score и сигналов модели.
- Семь тестов держат это свойство под разными углами: `TestEmergencyEitherSide`,
  `TestEmergencyWinsOverAllowlist` (`protect_test.go`), `TestEmergencyOverHTTP` (`api_test.go`),
  `TestEmergencyNeverBlocked`, `TestEmergencyNeverBlockedStillHoldsWithFloor` (`decide_test.go`),
  `TestEmergencyAlwaysAllowedEvenWithFraudSignals` (`engine_test.go`),
  `TestEmergencyNeverReachesML` (`cascade_test.go`).
- Счётчик экстренных вызовов — `internal/api/metrics.go:42` (`redflag_emergency_total`),
  инкремент — `internal/decision/engine/engine.go:314`; в офлайн-отчёте о качестве модели —
  `services/ml/training/evaluate.py:165-203`, поле `emergency.blocked` (должно быть 0).

**Акцент на FPR:**
- Цели по ложным срабатываниям — параметры обучения `services/ml/training/train.py`
  (`review_fpr`, `block_fpr`), раздельно для порога проверки и порога блока.
- `cmd/scorefile` — офлайн-прогон закрытого набора тем же движком, что и прод: решение и объяснение
  на каждый вызов, при наличии разметки — сводка полноты и FPR отдельно для `review`/`block`, плюс
  отдельно экстренные.

**Официальный датасет кейса уже прогнан:**
- `cmd/cdrflag` — прогон каталога `CDR_*.cdr` через боевой движок, выгрузка `submission.txt`
  (1641 номер, 2 352 113 вызовов, 0 ошибок скоринга). Независимая кросс-валидация с собственным
  разбором данных — [ADR-0019](adr/0019-case-dataset-detectors.md): 1648 из 1658 совпадений по
  структурным сигналам.

## 7. «Стек: Python, CatBoost или scikit-learn, NetworkX, FastAPI»

ML-сервис (стадия 2 каскада) — ровно этот стек:
- FastAPI — `services/ml/app/main.py:156` (`FastAPI(title="RedFlag ML service", ...)`)
- CatBoost — `services/ml/training/train.py` (`CatBoostClassifier`), `services/ml/app/model.py`
- scikit-learn — калибровка Платта (`LogisticRegression`), `GroupShuffleSplit`, метрики
- NetworkX — офлайн кросс-валидация графовых признаков при обучении, `services/ml/training/graphfeat.py`
  (`import networkx as nx`); не в горячем пути, обоснование — [ADR-0018](adr/0018-networkx-graph-analysis.md)

Ядро (стадия 1, оркестрация, HTTP API) — на Go, не Python. Это не самовольное отступление:
[ADR-0001](adr/0001-go-core.md) фиксирует прямое указание владельца и обоснование (единый бинарь,
меньше точек отказа); ADR-0010 позже вынес ML в отдельный Python-сервис, не трогая ядро.

## Известные, честно задокументированные ограничения

Не скрыты, а явно проговорены в [ADR-0019](adr/0019-case-dataset-detectors.md):

- **S7 (фишинг со спуфингом) не реализован.** Несколько попыток не нашли совпадений на официальном
  датасете — либо сценария в конкретном 5-суточном срезе нет, либо нужен признак (страна/оператор
  источника), которого в урезанном CDR-формате кейса физически нет. Эвристический детектор «на всякий
  случай» сознательно не добавлен: риск ложных срабатываний на датасете, где они прямо штрафуются,
  выше пользы от непроверенной догадки.
- **`MaxLeak=4` у карусельного детектора** — калибровка по единственному доступному датасету, не
  универсальная константа.
- **Стадия 1 не переобучена на датасете кейса** — у организаторов нет разметки; слепое дообучение на
  собственных эвристических метках было бы круговой проверкой. Веса новых признаков расставлены по
  аналогии с уже откалиброванными, подстрахованы тем, что все четыре — `HardSignals` (решение
  floor'ится структурной уликой независимо от веса модели).
