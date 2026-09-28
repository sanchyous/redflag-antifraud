// Package engine — ядро скоринга вызовов: собирает обогащение, окна, граф, защитный слой,
// модель и композицию вердикта в один поток обработки. Горячий путь не ходит в сеть и
// диск: всё состояние в памяти процесса.
package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/callrec"
	"github.com/sanchyous/redflag-antifraud/internal/decide"
	"github.com/sanchyous/redflag-antifraud/internal/enrich"
	"github.com/sanchyous/redflag-antifraud/internal/explain"
	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/graph"
	"github.com/sanchyous/redflag-antifraud/internal/numplan"
	"github.com/sanchyous/redflag-antifraud/internal/phone"
	"github.com/sanchyous/redflag-antifraud/internal/protect"
	"github.com/sanchyous/redflag-antifraud/internal/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/window"
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
	Duplicate       bool             `json:"duplicate,omitempty"`
	ModelVersion    string           `json:"model_version"`
	NumplanVersion  string           `json:"numplan_version,omitempty"`
	LatencyUS       int64            `json:"latency_us"`
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
	// MaxFutureSkew — максимальный допустимый уход started_at вперёд относительно часов сервера;
	// 0 — не проверять (по умолчанию: исторические данные и несинхронные часы источника).
	MaxFutureSkew time.Duration
	// ExplainAlways — формировать причины и для allow.
	ExplainAlways bool
}

// Metrics — счётчики решений (атомарные, для /metrics).
type Metrics struct {
	Allow, Review, Block, Duplicates, Errors, Emergency, Suppressed atomic.Uint64
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
	class  *protect.Classifier
	now    func() time.Time

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

	fillParties(&resp, &a.Res)
	resp.Decision = d.Verdict.String()
	resp.Score = float64(int(float64(ex.Score)*10000+0.5)) / 10000
	resp.Duplicate = a.Dup
	resp.BlockSuppressed = d.BlockSuppressed
	resp.SafeClass = a.Class.String()
	resp.Signals = sig.Names()
	if d.Verdict != decide.Allow || e.cfg.ExplainAlways {
		resp.Reasons = explain.Reasons(&ex, 0.05, 6, 2)
	} else {
		resp.Reasons = []explain.Reason{}
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
	profiles := e.win.Profiles(e.now().Unix(), e.cfg.FanSpan, e.cfg.Fan.MinCallsOrDefault())
	ix := graph.Analyze(profiles, e.cfg.Fan)
	e.fan.Store(ix)
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
	ft := time.NewTicker(fanEvery)
	st := time.NewTicker(sweepEvery)
	defer ft.Stop()
	defer st.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ft.C:
			e.RefreshFan()
		case <-st.C:
			now := e.now().Unix()
			e.win.Sweep(now)
			e.dedupe.Sweep(now)
		}
	}
}
