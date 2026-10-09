package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decision/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/detection/protect"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/callrec"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/numplan"
)

var t0 = time.Date(2026, 10, 14, 11, 42, 0, 0, time.UTC)

// testPlan: коды 900..939 — по одному региону на код (40 регионов), 495 — Москва (МГТС).
func testPlan(t testing.TB) *numplan.Plan {
	var sb strings.Builder
	sb.WriteString("АВС/ DEF;От;До;Емкость;Оператор;Регион;Территория ГАР;ИНН\n")
	sb.WriteString("495;0000000;9999999;10000000;ПАО МГТС;г. Москва;Город Москва;7710016640\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&sb, "%d;0000000;9999999;10000000;ПАО \"МТС\";-;Регион %02d;7740000076\n", 900+i, i)
	}
	b := numplan.NewBuilder()
	if err := b.AddCSV(strings.NewReader(sb.String())); err != nil {
		t.Fatal(err)
	}
	p, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type clock struct{ ts atomic.Int64 }

func (c *clock) Now() time.Time    { return time.Unix(c.ts.Load(), 0).UTC() }
func (c *clock) Advance(sec int64) { c.ts.Add(sec) }

func newEngine(t testing.TB, mut func(*Config)) (*Engine, *clock) {
	clk := &clock{}
	clk.ts.Store(t0.Unix())
	cfg := Config{Plan: testPlan(t), Now: clk.Now}
	if mut != nil {
		mut(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e, clk
}

func call(id, caller, callee string, ts time.Time, dur int) *callrec.Call {
	return &callrec.Call{CallID: id, Caller: caller, Callee: callee, StartedAt: ts, DurationSec: dur}
}

func TestTZScenarioReview(t *testing.T) {
	// Пример из ТЗ: +7 495 ***-**-12 → +7 916 ***-**-83, 14 октября 11:42, 6 секунд, вход из-за рубежа.
	e, _ := newEngine(t, nil)
	c := call("tz-1", "+7 495 ***-**-12", "+7 916 ***-**-83", t0, 6)
	c.SrcCountry = "DE"
	r, err := e.Score(c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision != "review" {
		t.Fatalf("decision = %s score=%v reasons=%+v", r.Decision, r.Score, r.Reasons)
	}
	if r.Caller.Masked != "+7 495 ***-**-12" || r.Callee.Masked != "+7 916 ***-**-83" {
		t.Fatalf("parties = %+v / %+v", r.Caller, r.Callee)
	}
	if r.Caller.Region != "Москва и Московская область" {
		t.Fatalf("caller region = %q", r.Caller.Region)
	}
	if !hasFactor(r, "spoof") || !hasFactor(r, "foreign_ingress") {
		t.Fatalf("reasons must explain the spoof: %+v", r.Reasons)
	}
	for _, rs := range r.Reasons {
		if rs.Text == "" {
			t.Fatalf("reason without text: %+v", rs)
		}
	}
	if len(r.Signals) != 1 || r.Signals[0] != "spoof" {
		t.Fatalf("signals = %v", r.Signals)
	}
	if r.ModelVersion == "" || r.NumplanVersion == "" {
		t.Fatal("versions must be reported")
	}
}

func hasFactor(r Response, f string) bool {
	for _, x := range r.Reasons {
		if x.Factor == f {
			return true
		}
	}
	return false
}

func TestOrdinaryCallAllowed(t *testing.T) {
	e, _ := newEngine(t, nil)
	r, err := e.Score(call("ok-1", "+7 916 123-45-67", "+7 495 765-43-21", t0, 180))
	if err != nil || r.Decision != "allow" || r.Score > 0.05 {
		t.Fatalf("resp = %+v err=%v", r, err)
	}
	if r.Reasons == nil || len(r.Reasons) != 0 {
		t.Fatalf("allow must carry an empty non-nil reasons list: %#v", r.Reasons)
	}
}

func TestEmergencyAlwaysAllowedEvenWithFraudSignals(t *testing.T) {
	e, _ := newEngine(t, nil)
	for _, callee := range []string{"103", "112", "*112#", "0103", "+112"} {
		c := call("em-"+callee, "+7 495 123-45-67", callee, t0, 2) // подмена + вход из-за рубежа + короткий
		c.SrcCountry = "DE"
		r, err := e.Score(c)
		if err != nil {
			t.Fatalf("%s: %v", callee, err)
		}
		if r.Decision != "allow" || r.SafeClass != "emergency" {
			t.Fatalf("%s: %+v", callee, r)
		}
	}
	// обратный звонок диспетчера человеку
	r, err := e.Score(call("em-cb", "103", "+7 916 123-45-67", t0, 40))
	if err != nil || r.Decision != "allow" || r.SafeClass != "emergency" {
		t.Fatalf("callback: %+v %v", r, err)
	}
	if e.Windows().Len() != 0 {
		t.Fatal("emergency calls must not pollute windows")
	}
	if e.Metrics.Emergency.Load() != 6 {
		t.Fatalf("emergency metric = %d", e.Metrics.Emergency.Load())
	}
}

// Сценарий обзвона: один номер бьёт по 40 регионам короткими вызовами → block.
func sweep(e *Engine, clk *clock, caller string, n int) (last Response) {
	for i := 0; i < n; i++ {
		callee := fmt.Sprintf("+7 %d 555-%04d", 900+i%40, i)
		c := call(fmt.Sprintf("%s-%d", caller, i), caller, callee, clk.Now(), 3)
		c.SrcCountry = "DE"
		last, _ = e.Score(c)
		clk.Advance(20)
	}
	return last
}

func TestMassCallerEscalatesToBlock(t *testing.T) {
	e, clk := newEngine(t, nil)
	r := sweep(e, clk, "+7 495 700-00-01", 90)
	if r.Decision != "block" {
		t.Fatalf("decision = %s score=%v signals=%v reasons=%+v", r.Decision, r.Score, r.Signals, r.Reasons)
	}
	if len(r.Signals) < 2 {
		t.Fatalf("block needs >= 2 signals: %v", r.Signals)
	}
	if !hasFactor(r, "out_calls_1h") && !hasFactor(r, "out_regions_24h") {
		t.Fatalf("expected campaign factors: %+v", r.Reasons)
	}
}

func TestAllowlistedMassCallerNeverBlocked(t *testing.T) {
	cl := protect.New()
	cl.Add("+7 495 700-00-01")
	e, clk := newEngine(t, func(c *Config) { c.Classifier = cl })
	r := sweep(e, clk, "+7 495 700-00-01", 90)
	if r.Decision == "block" {
		t.Fatalf("allowlisted caller blocked: %+v", r)
	}
	if r.Decision != "review" || !r.BlockSuppressed || r.SafeClass != "allowlisted" {
		t.Fatalf("expected review with suppression: %+v", r)
	}
	if e.Metrics.Suppressed.Load() == 0 {
		t.Fatal("suppression metric must count")
	}
}

func TestHeavyLegitimateUserAllowed(t *testing.T) {
	e, clk := newEngine(t, nil)
	var r Response
	for i := 0; i < 40; i++ { // 40 разговоров за день, длинные, повторяющиеся собеседники
		callee := fmt.Sprintf("+7 916 200-00-%02d", i%6)
		r, _ = e.Score(call(fmt.Sprintf("h-%d", i), "+7 916 123-45-67", callee, clk.Now(), 240))
		clk.Advance(1200)
	}
	if r.Decision != "allow" {
		t.Fatalf("legit heavy user: %+v", r)
	}
}

func TestDuplicateNotCountedTwice(t *testing.T) {
	e, _ := newEngine(t, nil)
	c := call("dup-1", "+7 916 123-45-67", "+7 495 765-43-21", t0, 60)
	if r, _ := e.Score(c); r.Duplicate {
		t.Fatal("first delivery is not a duplicate")
	}
	cp := *c
	r2, _ := e.Score(&cp)
	if !r2.Duplicate {
		t.Fatal("second delivery must be flagged duplicate")
	}
	n, _ := phoneKey("+7 916 123-45-67")
	if f := e.Windows().Peek(n, true, t0.Unix()); f.Calls24h != 1 {
		t.Fatalf("duplicate counted in windows: %d", f.Calls24h)
	}
	if e.Metrics.Duplicates.Load() != 1 {
		t.Fatal("duplicate metric")
	}
}

func TestDuplicateOfBlockedCallStaysBlocked(t *testing.T) {
	e, clk := newEngine(t, nil)
	sweep(e, clk, "+7 495 700-00-02", 90)
	// повторная доставка последнего вызова кампании
	c := call("+7 495 700-00-02-89", "+7 495 700-00-02", "+7 929 555-0089", clk.Now(), 3)
	c.SrcCountry = "DE"
	r, _ := e.Score(c)
	if !r.Duplicate {
		t.Fatal("expected duplicate")
	}
	if r.Decision == "allow" {
		t.Fatalf("redelivery of a campaign call must not turn into allow: %+v", r)
	}
}

func TestValidationErrors(t *testing.T) {
	e, _ := newEngine(t, nil)
	cases := map[string]*callrec.Call{
		"call_id_required":  call("", "+7 916 123-45-67", "+7 495 765-43-21", t0, 5),
		"callee_required":   call("v1", "+7 916 123-45-67", "", t0, 5),
		"duration_negative": call("v2", "+7 916 123-45-67", "+7 495 765-43-21", t0, -1),
		"callee_invalid":    call("v4", "+7 916 123-45-67", "не номер", t0, 5),
	}
	for want, c := range cases {
		_, err := e.Score(c)
		var ve *ValidationError
		if !errors.Is(err, ErrInvalidCall) || !errors.As(err, &ve) || ve.Codes[0] != want {
			t.Fatalf("%s: err = %v", want, err)
		}
	}
	if e.Metrics.Errors.Load() != 4 {
		t.Fatalf("errors metric = %d", e.Metrics.Errors.Load())
	}
}

func TestFutureTimestampPolicy(t *testing.T) {
	future := call("fut-1", "+7 916 123-45-67", "+7 495 765-43-21", t0.Add(5*time.Hour), 5)
	e, _ := newEngine(t, nil)
	if _, err := e.Score(future); err != nil {
		t.Fatalf("by default future timestamps are accepted (replay of historical data): %v", err)
	}
	strict, _ := newEngine(t, func(c *Config) { c.MaxFutureSkew = time.Hour })
	future2 := call("fut-2", "+7 916 123-45-67", "+7 495 765-43-21", t0.Add(5*time.Hour), 5)
	var ve *ValidationError
	if _, err := strict.Score(future2); !errors.As(err, &ve) || ve.Codes[0] != "started_at_in_future" {
		t.Fatalf("strict mode: %v", err)
	}
}

func TestMissingStartedAtUsesServerTime(t *testing.T) {
	e, _ := newEngine(t, nil)
	c := call("ts-1", "+7 916 123-45-67", "+7 495 765-43-21", time.Time{}, 60)
	if _, err := e.Score(c); err != nil {
		t.Fatal(err)
	}
	if !c.StartedAt.Equal(t0) {
		t.Fatalf("StartedAt = %v, want server time %v", c.StartedAt, t0)
	}
}

func TestFanDetectionFeedsScoring(t *testing.T) {
	e, clk := newEngine(t, nil)
	// 6 номеров с общим шаблоном (короткие, каждые 60 с) и непересекающимися списками
	for i := 0; i < 40; i++ {
		for k := 0; k < 6; k++ {
			caller := fmt.Sprintf("+7 916 800-00-%02d", k)
			callee := fmt.Sprintf("+7 9%02d %03d-%02d-%02d", 10+k, i, k, i)
			e.Score(call(fmt.Sprintf("f-%d-%d", i, k), caller, callee, clk.Now(), 4))
		}
		clk.Advance(60)
	}
	ix := e.RefreshFan()
	if ix.Groups() != 1 || ix.Members() != 6 {
		t.Fatalf("groups=%d members=%d", ix.Groups(), ix.Members())
	}
	r, _ := e.Score(call("f-next", "+7 916 800-00-03", "+7 916 333-33-33", clk.Now(), 4))
	if !hasFactor(r, "fan_member") {
		t.Fatalf("fan membership must be explained: %+v", r)
	}
	found := false
	for _, s := range r.Signals {
		if s == "fan" {
			found = true
		}
	}
	if !found {
		t.Fatalf("signals = %v", r.Signals)
	}
}

func TestSubscriberFarmSignal(t *testing.T) {
	e, clk := newEngine(t, func(c *Config) { c.ExplainAlways = true })
	var r Response
	for k := 0; k < 12; k++ {
		c := call(fmt.Sprintf("s-%d", k), fmt.Sprintf("+7 916 900-00-%02d", k), "+7 495 765-43-21", clk.Now(), 30)
		c.SubscriberID = "abonent-1"
		r, _ = e.Score(c)
	}
	if !hasFactor(r, "subscriber_numbers") {
		t.Fatalf("subscriber farm must be explained: %+v", r)
	}
}

func TestSimCloneSignal(t *testing.T) {
	e, clk := newEngine(t, func(c *Config) { c.ExplainAlways = true })
	var r Response
	for k := 0; k < 4; k++ { // один и тот же номер, 4 разных IMSI
		c := call(fmt.Sprintf("imsi-%d", k), "+7 916 111-22-33", "+7 495 765-43-21", clk.Now(), 30)
		c.IMSI = fmt.Sprintf("2500%011d", k)
		r, _ = e.Score(c)
		clk.Advance(60)
	}
	if !hasFactor(r, "imsi_count") {
		t.Fatalf("imsi clone must be explained: %+v", r)
	}
	if !containsSignal(r, "sim_clone") {
		t.Fatalf("signals = %v", r.Signals)
	}
}

func TestForwardChainSignal(t *testing.T) {
	e, clk := newEngine(t, func(c *Config) { c.ExplainAlways = true })
	// B → C → D: два перехода переадресации, статично повторяются несколько раз.
	for k := 0; k < 3; k++ {
		b2c := call(fmt.Sprintf("fwd-bc-%d", k), "+7 916 000-00-01", "+7 916 000-00-02", clk.Now(), 10)
		b2c.Direction, b2c.ForwardTo = "forwarded", "+7 916 000-00-03"
		e.Score(b2c)
		c2d := call(fmt.Sprintf("fwd-cd-%d", k), "+7 916 222-00-01", "+7 916 000-00-03", clk.Now(), 10)
		c2d.Direction, c2d.ForwardTo = "forwarded", "+7 916 000-00-04"
		e.Score(c2d)
		clk.Advance(60)
	}
	ix := e.RefreshChains()
	if ix.Members() != 3 {
		t.Fatalf("chain members = %d, want 3 (B, C, D)", ix.Members())
	}
	r, _ := e.Score(call("plain-from-b", "+7 916 000-00-02", "+7 916 999-99-99", clk.Now(), 10))
	if !hasFactor(r, "chain_member") {
		t.Fatalf("chain membership must be explained: %+v", r)
	}
	if !containsSignal(r, "forward_chain") {
		t.Fatalf("signals = %v", r.Signals)
	}
}

func TestSimBoxSignal(t *testing.T) {
	e, clk := newEngine(t, func(c *Config) { c.ExplainAlways = true })
	for i := 0; i < 60; i++ { // только исходящие, всегда новому собеседнику, обычная длительность
		callee := fmt.Sprintf("+7 9%02d %03d-%02d-%02d", 10+i%30, i, i%10, i%100)
		e.Score(call(fmt.Sprintf("sb-%d", i), "+7 916 444-00-00", callee, clk.Now(), 90))
		clk.Advance(60)
	}
	ix := e.RefreshSimBox()
	if ix.Members() != 1 {
		t.Fatalf("sim-box members = %d, want 1", ix.Members())
	}
	r, _ := e.Score(call("sb-next", "+7 916 444-00-00", "+7 916 555-00-00", clk.Now(), 90))
	if !hasFactor(r, "simbox_member") {
		t.Fatalf("sim-box membership must be explained: %+v", r)
	}
	if !containsSignal(r, "sim_box") {
		t.Fatalf("signals = %v", r.Signals)
	}
}

func TestSimBoxSpanCoversMoreThanAnHour(t *testing.T) {
	// Регрессия: SIM-box — устойчивый паттерн на днях, не всплеск. Раньше SimBox/Carousel
	// пересчитывались по тому же часовому окну, что и веер (FanSpan=3600с по умолчанию), и
	// вызовы, растянутые на сутки, в него просто не помещались — живой прогон cmd/cdrflag на
	// официальном датасете кейса находил 0 SIM-box вместо ожидаемых по независимому анализу
	// сотен. Раскладываем те же 60 вызовов на 5 часов (за пределы часового FanSpan, но в
	// пределах суточного SimBoxSpan по умолчанию).
	e, clk := newEngine(t, func(c *Config) { c.ExplainAlways = true })
	for i := 0; i < 60; i++ {
		callee := fmt.Sprintf("+7 9%02d %03d-%02d-%02d", 10+i%30, i, i%10, i%100)
		e.Score(call(fmt.Sprintf("sbs-%d", i), "+7 916 444-11-11", callee, clk.Now(), 90))
		clk.Advance(300) // 5 мин между вызовами × 60 = 5 часов общего разброса
	}
	ix := e.RefreshSimBox()
	if ix.Members() != 1 {
		t.Fatalf("sim-box members = %d, want 1 (span must cover the full 5h spread)", ix.Members())
	}
}

func TestCarouselSignal(t *testing.T) {
	e, clk := newEngine(t, func(c *Config) { c.ExplainAlways = true })
	group := []string{"+7 916 700-00-01", "+7 916 700-00-02", "+7 916 700-00-03", "+7 916 700-00-04", "+7 916 700-00-05"}
	id := 0
	for round := 0; round < 30; round++ { // каждый с каждым, 30 раундов: по 120 исходящих на номер
		for i, a := range group {
			for j, b := range group {
				if i == j {
					continue
				}
				e.Score(call(fmt.Sprintf("car-%d", id), a, b, clk.Now(), 20))
				id++
			}
		}
		clk.Advance(10)
	}
	ix := e.RefreshCarousel()
	if ix.Members() != 5 {
		t.Fatalf("carousel members = %d, want 5", ix.Members())
	}
	r, _ := e.Score(call("car-next", group[0], group[1], clk.Now(), 20))
	if !hasFactor(r, "carousel_member") {
		t.Fatalf("carousel membership must be explained: %+v", r)
	}
	if !containsSignal(r, "carousel") {
		t.Fatalf("signals = %v", r.Signals)
	}
}

// TestCarouselSignalIncludesPassiveMembers — регрессия для ранее известного ограничения
// (CarouselConfig.MaxLeak): участники карусели, которые в основном отвечают и сами звонят
// редко, раньше не набирали MinCalls по одним исходящим и не попадали в индекс вовсе.
// RefreshCarousel теперь строит кандидатов по обеим сторонам (ProfilesAllDirections), и
// пассивный участник должен быть виден наравне с активными.
func TestCarouselSignalIncludesPassiveMembers(t *testing.T) {
	e, clk := newEngine(t, func(c *Config) { c.ExplainAlways = true })
	active := []string{"+7 916 701-00-01", "+7 916 701-00-02", "+7 916 701-00-03", "+7 916 701-00-04", "+7 916 701-00-05"}
	passive := []string{"+7 916 701-00-06", "+7 916 701-00-07"}
	all := append(append([]string{}, active...), passive...)
	id := 0
	for round := 0; round < 30; round++ { // активные звонят всем в группе, включая молчунов
		for _, a := range active {
			for _, b := range all {
				if a == b {
					continue
				}
				e.Score(call(fmt.Sprintf("car-p-%d", id), a, b, clk.Now(), 20))
				id++
			}
		}
		clk.Advance(10)
	}
	ix := e.RefreshCarousel()
	if ix.Members() != 7 {
		t.Fatalf("carousel members = %d, want 7 (5 active + 2 passive)", ix.Members())
	}
	// Молчун наконец звонит сам — проверяем, что живой скоринг тоже видит его членство.
	r, _ := e.Score(call("car-p-next", passive[0], active[0], clk.Now(), 20))
	if !hasFactor(r, "carousel_member") {
		t.Fatalf("passive member's own call must be explained by carousel membership: %+v", r)
	}
	if !containsSignal(r, "carousel") {
		t.Fatalf("signals = %v", r.Signals)
	}
}

func containsSignal(r Response, name string) bool {
	for _, s := range r.Signals {
		if s == name {
			return true
		}
	}
	return false
}

func TestModelHotSwap(t *testing.T) {
	e, _ := newEngine(t, nil)
	c := func(id string) *callrec.Call {
		x := call(id, "+7 495 123-45-67", "+7 916 123-45-67", t0, 6)
		x.SrcCountry = "DE"
		return x
	}
	before, _ := e.Score(c("m-1"))
	m := scoring.Prior()
	m.Version = "prior-x"
	m.W[0] = 0 // безразлично
	m.Review, m.Block = 0.9999, 1
	e.SetModel(m)
	after, _ := e.Score(c("m-2"))
	if after.ModelVersion != "prior-x" || before.ModelVersion == after.ModelVersion {
		t.Fatalf("model not swapped: %s → %s", before.ModelVersion, after.ModelVersion)
	}
	// Пороги новой модели строгие (0.9999), но подмена номера — жёсткое правило: пол review остаётся.
	if after.Decision != "review" || !after.RuleFloor {
		t.Fatalf("hard evidence must floor the verdict even with strict thresholds: %+v", after)
	}
	// а обычный вызов по новым порогам остаётся allow
	if ord, _ := e.Score(call("m-3", "+7 916 123-45-67", "+7 495 765-43-21", t0, 200)); ord.Decision != "allow" {
		t.Fatalf("ordinary call: %+v", ord)
	}
}

func TestConcurrentScoring(t *testing.T) {
	e, _ := newEngine(t, nil)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				c := call(fmt.Sprintf("c-%d-%d", g, i), fmt.Sprintf("+7 916 100-%02d-%02d", g, i%50),
					fmt.Sprintf("+7 %d 300-%02d-%02d", 900+i%40, g, i%100), t0.Add(time.Duration(i)*time.Second), i%120)
				if _, err := e.Score(c); err != nil {
					t.Error(err)
					return
				}
				if i%200 == 0 {
					e.RefreshFan()
				}
			}
		}(g)
	}
	wg.Wait()
	total := e.Metrics.Allow.Load() + e.Metrics.Review.Load() + e.Metrics.Block.Load()
	if total != 8000 {
		t.Fatalf("decisions counted = %d", total)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	e, _ := newEngine(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx, 5*time.Millisecond, 5*time.Millisecond); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
	if e.Fan() == nil {
		t.Fatal("Run must have published a fan index")
	}
}

func TestNewRejectsInvalidModel(t *testing.T) {
	m := scoring.Prior()
	m.Review = 0
	if _, err := New(Config{Model: m}); err == nil {
		t.Fatal("invalid model must be rejected")
	}
}

func benchCalls(n int) []callrec.Call {
	cs := make([]callrec.Call, n)
	for i := range cs {
		u := uint64(i)
		cs[i] = callrec.Call{
			CallID:    fmt.Sprintf("b-%d", i),
			Caller:    fmt.Sprintf("+7 916 %03d-%02d-%02d", u%1000, u%100, (u/7)%100),
			Callee:    fmt.Sprintf("+7 9%02d %03d-%02d-%02d", 10+u%30, (u/3)%1000, u%100, u%97),
			StartedAt: t0.Add(time.Duration(i%3000) * time.Second), DurationSec: i % 200,
		}
	}
	return cs
}

func BenchmarkScoreParallel(b *testing.B) {
	e, _ := newEngine(b, nil)
	cs := benchCalls(1 << 18)
	var n atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := n.Add(1)
			c := cs[i&(1<<18-1)]
			c.CallID = cs[i&(1<<18-1)].CallID + string(rune('a'+i>>18%26)) // уникальность между оборотами
			if _, err := e.Score(&c); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkScoreSingleThread(b *testing.B) {
	e, _ := newEngine(b, nil)
	cs := benchCalls(1 << 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := cs[i&(1<<16-1)]
		c.CallID += string(rune('a' + (i>>16)%26))
		if _, err := e.Score(&c); err != nil {
			b.Fatal(err)
		}
	}
}
