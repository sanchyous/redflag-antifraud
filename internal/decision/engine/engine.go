// Package engine — ядро скоринга вызовов: собирает обогащение, окна, граф, защитный слой,
// модель и композицию вердикта в один поток обработки. Горячий путь не ходит в сеть и
// диск: всё состояние в памяти процесса.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decision/decide"
	"github.com/sanchyous/redflag-antifraud/internal/decision/explain"
	"github.com/sanchyous/redflag-antifraud/internal/decision/mlclient"
	"github.com/sanchyous/redflag-antifraud/internal/decision/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/detection/enrich"
	"github.com/sanchyous/redflag-antifraud/internal/detection/features"
	"github.com/sanchyous/redflag-antifraud/internal/detection/graph"
	"github.com/sanchyous/redflag-antifraud/internal/detection/protect"
	"github.com/sanchyous/redflag-antifraud/internal/detection/window"
	"github.com/sanchyous/redflag-antifraud/internal/platform/logx"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/callrec"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/numplan"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/phone"
)

// ErrInvalidCall — вызов не прошёл структурную валидацию; список кодов — в *ValidationError.
var ErrInvalidCall = errors.New("engine: invalid call")

// ValidationError несёт коды ошибок валидации.
type ValidationError struct{ Codes []string }

func (e *ValidationError) Error() string { return "invalid call: " + e.Codes[0] }
func (e *ValidationError) Unwrap() error { return ErrInvalidCall }

// Party — сторона вызова в ответе. Номера только в маскированном виде.
type Party struct {
	Masked   string `json:"masked"`
	Country  string `json:"country,omitempty"`
	Region   string `json:"region,omitempty"`
	Operator string `json:"operator,omitempty"`
}

// Response — результат скоринга вызова.
type Response struct {
	CallID          string           `json:"call_id"`
	Decision        string           `json:"decision"`
	Score           float64          `json:"score"`
	Reasons         []explain.Reason `json:"reasons"`
	Signals         []string         `json:"signals,omitempty"`
	Caller          Party            `json:"caller"`
	Callee          Party            `json:"callee"`
	SafeClass       string           `json:"safe_class,omitempty"`
	BlockSuppressed bool             `json:"block_suppressed,omitempty"`
	// RuleFloor — модель не сочла вызов рискованным, но сработало жёсткое правило (подмена номера
	// или нераспределённый CLI): вердикт поднят до review.
	RuleFloor bool `json:"rule_floor,omitempty"`
	Duplicate bool `json:"duplicate,omitempty"`
	// Stage — какая стадия приняла решение: "linear" (ядро) или "ml" (ML-сервис).
	Stage          string `json:"stage"`
	ModelVersion   string `json:"model_version"`
	NumplanVersion string `json:"numplan_version,omitempty"`
	LatencyUS      int64  `json:"latency_us"`
}

// Config — зависимости и параметры ядра.
type Config struct {
	Plan       *numplan.Plan       // nil — без региональных признаков
	Classifier *protect.Classifier // nil — пустой allowlist
	Model      *scoring.Model      // nil — априорная модель
	Policy     decide.Policy       // нулевые Review/Block берутся из модели
	Window     window.Config
	Fan        graph.Config
	// FanSpan — период профилей для поиска вееров (по умолчанию 3600 с).
	FanSpan uint32
	Loc     *time.Location
	Now     func() time.Time // источник времени (тесты)
	// ML — клиент ML-сервиса (стадия 2 каскада). nil — только стадия 1.
	ML *mlclient.Client
	// Log — логгер движка: события состояния (активация и отключение ML, обновление вееров, очистка).
	// nil — без логирования.
	Log *slog.Logger
	// MLRetryEvery — как часто проверять ML-сервис, пока стадия 2 неактивна (по умолчанию 5 с): после
	// перезапуска ядро стартует раньше ML и должно подхватить его сразу, а не через минуту.
	MLRetryEvery time.Duration
	// OnMLError вызывается при неудачном обновлении описания ML-модели (логирование).
	OnMLError func(error)
	// MaxFutureSkew — максимальный допустимый уход started_at вперёд относительно часов сервера;
	// 0 — не проверять (по умолчанию: исторические данные и несинхронные часы источника).
	MaxFutureSkew time.Duration
	// ExplainAlways — формировать причины и для allow.
	ExplainAlways bool
}

// Metrics — счётчики решений (атомарные, для /metrics).
type Metrics struct {
	Allow, Review, Block, Duplicates, Errors, Emergency, Suppressed atomic.Uint64
	// Каскад: вызовы в ML, сбои ML, вызовы, обойдённые открытым breaker'ом, решения стадии 2.
	MLCalls, MLErrors, MLSkipped, MLDecisions atomic.Uint64
	RuleFloors                                atomic.Uint64 // вердикт поднят до review жёстким правилом
}

// mlState — то, что ядро знает о ML-модели: политика и ворота, подобранные при обучении.
type mlState struct {
	Policy  decide.Policy
	Gate    float32
	Version string
	Info    mlclient.Info
}

// Engine безопасен для конкурентного использования.
type Engine struct {
	cfg    Config
	enrich *enrich.Enricher
	win    *window.Store
	dedupe *window.Dedupe
	subs   *graph.Subscribers
	fan    graph.Holder
	model  atomic.Pointer[scoring.Model]
	policy atomic.Pointer[decide.Policy]
	ml     atomic.Pointer[mlState]
	class  *protect.Classifier
	now    func() time.Time
	log    *slog.Logger

	Metrics Metrics
}

// New собирает движок.
func New(cfg Config) (*Engine, error) {
	if cfg.Model == nil {
		cfg.Model = scoring.Prior()
	}
	if err := cfg.Model.Validate(); err != nil {
		return nil, err
	}
	if cfg.Classifier == nil {
		cfg.Classifier = protect.New()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.FanSpan == 0 {
		cfg.FanSpan = 3600
	}
	e := &Engine{
		cfg:    cfg,
		enrich: enrich.New(cfg.Plan, cfg.Loc),
		win:    window.New(cfg.Window),
		dedupe: window.NewDedupe(0),
		subs:   graph.NewSubscribers(0),
		class:  cfg.Classifier,
		now:    cfg.Now,
		log:    logx.Component(cfg.Log, "engine"),
	}
	e.SetModel(cfg.Model)
	return e, nil
}

// SetModel атомарно подменяет модель (горячая перезагрузка). Политика берёт пороги из модели,
// если они не заданы явно в конфиге.
func (e *Engine) SetModel(m *scoring.Model) {
	p := e.cfg.Policy
	if p.Review <= 0 {
		p.Review = m.Review
	}
	if p.Block <= 0 {
		p.Block = m.Block
	}
	p = p.Defaults()
	e.model.Store(m)
	e.policy.Store(&p)
}

// Model возвращает текущую модель.
func (e *Engine) Model() *scoring.Model { return e.model.Load() }

// Fan возвращает текущий индекс вееров.
func (e *Engine) Fan() *graph.Index { return e.fan.Index() }

// Windows возвращает хранилище окон (для метрик и тестов).
func (e *Engine) Windows() *window.Store { return e.win }

// Analysis — результат стадий до модели: обогащение, защитный класс и вектор признаков.
// Обучение и оценка используют Analyze напрямую, поэтому признаки при обучении и в проде
// считаются одним и тем же кодом.
type Analysis struct {
	Res       enrich.Result
	Vec       features.Vector
	Class     protect.Class
	Emergency bool // вызов экстренной службы: вектор не считается, окна не пополняются
	RawOnly   bool // экстренная служба распознана по «сырой» записи, разбор сторон не выполнялся
	Dup       bool
}

// Analyze проходит стадии до модели. Побочный эффект — пополнение окон и счётчиков (кроме
// экстренных вызовов и дублей).
func (e *Engine) Analyze(c *callrec.Call) (Analysis, error) {
	var a Analysis
	now := e.now()

	// Экстренные службы — до любой валидации и парсинга: нестандартная запись ("*112#")
	// не должна стать ошибкой, а вызов — блокировкой. Окна не пополняем.
	if protect.IsEmergencyRaw(c.Callee) || protect.IsEmergencyRaw(c.Caller) {
		a.Emergency, a.RawOnly, a.Class = true, true, protect.Emergency
		return a, nil
	}
	if c.StartedAt.IsZero() {
		c.StartedAt = now
	}
	if errs := c.Validate(now, e.cfg.MaxFutureSkew); len(errs) > 0 {
		e.Metrics.Errors.Add(1)
		return a, &ValidationError{Codes: errs}
	}
	res, err := e.enrich.Enrich(c)
	if err != nil {
		e.Metrics.Errors.Add(1)
		return a, &ValidationError{Codes: []string{"callee_invalid"}}
	}
	a.Res = res
	a.Class = e.class.Classify(res.Caller.Num, res.Callee.Num, res.Caller.Valid)
	if a.Class == protect.Emergency {
		a.Emergency = true
		return a, nil
	}

	// Повторная доставка: считаем по накопленному состоянию, но не учитываем вызов второй раз.
	a.Dup = e.dedupe.Seen(c.CallID, res.Event.TS)
	var wf window.Features
	if a.Dup {
		e.Metrics.Duplicates.Add(1)
		wf.Out = e.win.Peek(res.Event.Caller, true, res.Event.TS)
		wf.In = e.win.Peek(res.Event.Callee, false, res.Event.TS)
	} else {
		wf = e.win.Observe(&res.Event)
	}
	in := features.Input{Res: &a.Res, Win: wf, ShortSec: e.cfg.Window.ShortSec}
	if fi, ok := e.fan.Lookup(res.Event.Caller); ok {
		in.Fan, in.InFan = fi, true
	}
	if res.Event.Subscriber != 0 && res.Caller.Valid {
		in.SubNums = e.subs.Observe(res.Event.Subscriber, res.Event.Caller)
	}
	features.Build(&in, &a.Vec)
	return a, nil
}

// Score обрабатывает один вызов. Вызов может быть изменён (подставляется StartedAt).
func (e *Engine) Score(c *callrec.Call) (Response, error) {
	start := time.Now()
	resp := Response{CallID: c.CallID, ModelVersion: e.model.Load().Version}
	if e.cfg.Plan != nil {
		resp.NumplanVersion = e.cfg.Plan.Version
	}
	a, err := e.Analyze(c)
	if err != nil {
		return resp, err
	}
	if a.Emergency {
		e.Metrics.Emergency.Add(1)
		e.Metrics.Allow.Add(1)
		resp.Decision = decide.Allow.String()
		resp.Stage = "linear"
		resp.SafeClass = protect.Emergency.String()
		resp.Reasons = []explain.Reason{}
		if a.RawOnly {
			resp.Caller.Masked = maskRaw(c.Caller)
			resp.Callee.Masked = maskRaw(c.Callee)
		} else {
			fillParties(&resp, &a.Res)
		}
		resp.LatencyUS = time.Since(start).Microseconds()
		return resp, nil
	}

	model, pol := e.model.Load(), e.policy.Load()
	var ex scoring.Explanation
	model.Score(&a.Vec, &ex)
	sig := pol.StrongSignals(&a.Vec)
	d := pol.Decide(a.Class, ex.Score, sig)
	score, stage, version := float64(ex.Score), "linear", model.Version
	var mlContribs []explain.MLContribution

	// Стадия 2: только «серая зона» — оценка стадии 1 не ниже ворот либо есть сильный сигнал.
	// Любой сбой ML (таймаут, breaker, некорректный ответ) — тихий откат на стадию 1.
	if st := e.ml.Load(); st != nil && e.cfg.ML != nil && (ex.Score >= st.Gate || sig != 0) {
		res, err := e.cfg.ML.Score(context.Background(), &a.Vec, true)
		switch {
		case err == nil:
			e.Metrics.MLCalls.Add(1)
			e.Metrics.MLDecisions.Add(1)
			d = st.Policy.Decide(a.Class, float32(res.Score), sig)
			score, stage, version = res.Score, "ml", res.ModelVersion
			for _, c := range res.Contributions {
				mlContribs = append(mlContribs, explain.MLContribution{Feature: c.Feature, Value: c.Value, Contribution: c.Contribution})
			}
		case errors.Is(err, mlclient.ErrBreakerOpen):
			e.Metrics.MLSkipped.Add(1)
		default:
			e.Metrics.MLCalls.Add(1)
			e.Metrics.MLErrors.Add(1)
		}
	}

	fillParties(&resp, &a.Res)
	resp.Decision = d.Verdict.String()
	resp.Score = float64(int(score*10000+0.5)) / 10000
	resp.Stage, resp.ModelVersion = stage, version
	resp.Duplicate = a.Dup
	resp.BlockSuppressed = d.BlockSuppressed
	resp.RuleFloor = d.Floored
	resp.SafeClass = a.Class.String()
	resp.Signals = sig.Names()
	switch {
	case d.Verdict == decide.Allow && !e.cfg.ExplainAlways:
		resp.Reasons = []explain.Reason{}
	case stage == "ml":
		resp.Reasons = explain.FromML(mlContribs, 0.05, 6, 2)
	default:
		resp.Reasons = explain.Reasons(&ex, 0.05, 6, 2)
	}
	if d.Floored {
		// Вердикт дало правило, а не модель: причина должна быть названа первой и своими словами.
		resp.Reasons = append([]explain.Reason{floorReason(sig)}, resp.Reasons...)
		e.Metrics.RuleFloors.Add(1)
	}
	switch d.Verdict {
	case decide.Block:
		e.Metrics.Block.Add(1)
	case decide.Review:
		e.Metrics.Review.Add(1)
	default:
		e.Metrics.Allow.Add(1)
	}
	if d.BlockSuppressed {
		e.Metrics.Suppressed.Add(1)
	}
	resp.LatencyUS = time.Since(start).Microseconds()
	return resp, nil
}

// Policy возвращает текущую политику решений.
func (e *Engine) Policy() decide.Policy { return *e.policy.Load() }

func fillParties(resp *Response, r *enrich.Result) {
	resp.Caller = party(&r.Caller)
	resp.Callee = party(&r.Callee)
}

// party описывает номер (страна — страна номера, а не входа: вход из-за рубежа виден в признаках).
func party(s *enrich.Side) Party {
	if !s.Valid {
		return Party{}
	}
	return Party{Masked: s.Num.Mask(), Country: s.Num.ISO, Region: s.Region, Operator: s.Operator}
}

// maskRaw маскирует «сырую» строку, которая, возможно, не разбирается как номер.
func maskRaw(raw string) string {
	if raw == "" {
		return ""
	}
	if n, err := phone.Parse(raw); err == nil {
		return n.Mask()
	}
	return "***"
}

// RefreshFan пересчитывает индекс вееров по снимку профилей окон.
func (e *Engine) RefreshFan() *graph.Index {
	start := time.Now()
	profiles := e.win.Profiles(e.now().Unix(), e.cfg.FanSpan, e.cfg.Fan.MinCallsOrDefault())
	ix := graph.Analyze(profiles, e.cfg.Fan)
	prev := e.fan.Index()
	e.fan.Store(ix)
	// Изменение состава вееров — событие (info); неизменный индекс — только debug, чтобы не шуметь раз в 30 секунд.
	lvl := slog.LevelDebug
	if prev.Groups() != ix.Groups() || prev.Members() != ix.Members() {
		lvl = slog.LevelInfo
	}
	e.log.Log(context.Background(), lvl, "fan_index_updated", "groups", ix.Groups(), "members", ix.Members(),
		"profiles", len(profiles), "took", time.Since(start).Round(time.Microsecond).String())
	return ix
}

// Run запускает фоновые задачи до отмены ctx: пересчёт вееров и очистка состояния.
func (e *Engine) Run(ctx context.Context, fanEvery, sweepEvery time.Duration) {
	if fanEvery <= 0 {
		fanEvery = 30 * time.Second
	}
	if sweepEvery <= 0 {
		sweepEvery = 5 * time.Minute
	}
	const mlEvery = time.Minute
	lastML := time.Now()
	retry := e.cfg.MLRetryEvery
	if retry <= 0 {
		retry = 5 * time.Second
	}
	ft := time.NewTicker(fanEvery)
	st := time.NewTicker(sweepEvery)
	mt := time.NewTicker(retry)
	defer ft.Stop()
	defer st.Stop()
	defer mt.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ft.C:
			e.RefreshFan()
		case <-mt.C:
			// Стадия неактивна — повторяем быстро; активна — перечитываем описание модели раз в минуту.
			if e.cfg.ML != nil && (e.ml.Load() == nil || time.Since(lastML) >= mlEvery) {
				lastML = time.Now()
				if err := e.RefreshML(ctx); err != nil && e.cfg.OnMLError != nil {
					e.cfg.OnMLError(err)
				}
			}
		case <-st.C:
			now := e.now().Unix()
			numbers, calls := e.win.Sweep(now), e.dedupe.Sweep(now)
			e.log.Debug("state_swept", "numbers_removed", numbers, "call_ids_removed", calls, "numbers_tracked", e.win.Len())
		}
	}
}

// RefreshML читает у ML-сервиса описание модели и обновляет пороги и ворота каскада.
// Проверяется контракт: список признаков ML должен совпадать со списком ядра; иначе стадия 2
// отключается (лучше стадия 1, чем оценка по рассинхронизированным признакам).
func (e *Engine) RefreshML(ctx context.Context) error {
	if e.cfg.ML == nil {
		return nil
	}
	inf, err := e.cfg.ML.Info(ctx)
	if err != nil {
		return err // текущее состояние не трогаем: временный сбой не должен отключать ML
	}
	fail := func(err error) error {
		if e.ml.Swap(nil) != nil {
			e.log.Error("ml_stage_disabled", "reason", err.Error())
		}
		return err
	}
	if len(inf.Features) != features.N {
		return fail(fmt.Errorf("engine: ML model has %d features, core has %d", len(inf.Features), features.N))
	}
	for i, n := range features.Names {
		if inf.Features[i] != n {
			return fail(fmt.Errorf("engine: ML feature %d is %q, core expects %q", i, inf.Features[i], n))
		}
	}
	th := inf.Thresholds
	review, block := float32(th["review"]), float32(th["block"])
	if !(review > 0 && review <= block && block <= 1) {
		return fail(fmt.Errorf("engine: ML thresholds invalid: review=%v block=%v", review, block))
	}
	gate := float32(th["gate"])
	if gate < 0 || gate > 1 {
		return fail(fmt.Errorf("engine: ML gate out of range: %v", gate))
	}
	pol := decide.Policy{Review: review, Block: block, MinStrong: int(th["min_signals"])}
	base := e.policy.Load()
	pol.BurstCalls1h, pol.BurstShare, pol.SweepRegions = base.BurstCalls1h, base.BurstShare, base.SweepRegions
	pol.FarmNumbers, pol.RobotIndex, pol.RobotCalls1h = base.FarmNumbers, base.RobotIndex, base.RobotCalls1h
	prev := e.ml.Swap(&mlState{Policy: pol.Defaults(), Gate: gate, Version: inf.Version, Info: inf})
	switch {
	case prev == nil:
		e.log.Info("ml_stage_ready", "version", inf.Version, "gate", gate, "review", review, "block", block)
	case prev.Version != inf.Version:
		e.log.Info("ml_model_changed", "from", prev.Version, "to", inf.Version, "gate", gate, "review", review, "block", block)
	}
	return nil
}

// WarmupML прогревает соединение и первый запрос к ML-сервису (ошибка не критична).
func (e *Engine) WarmupML(ctx context.Context) error {
	if e.cfg.ML == nil {
		return nil
	}
	return e.cfg.ML.Warmup(ctx)
}

// MLVersion возвращает версию активной ML-модели ("" — стадия 2 не активна).
func (e *Engine) MLVersion() string {
	if st := e.ml.Load(); st != nil {
		return st.Version
	}
	return ""
}

// floorReason описывает жёсткое правило, поднявшее вердикт до review.
func floorReason(sig decide.Signals) explain.Reason {
	if sig&decide.SigSpoof != 0 {
		return explain.Reason{Factor: "rule_spoof", Value: 1, Effect: "raises",
			Text: "правило: российский номер при иностранном входе (подмена номера) — не ниже review независимо от модели"}
	}
	return explain.Reason{Factor: "rule_unallocated", Value: 1, Effect: "raises",
		Text: "правило: номер вызывающего из нераспределённого диапазона — не ниже review независимо от модели"}
}
