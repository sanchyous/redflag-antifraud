package telemetry

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock — управляемые часы.
type fakeClock struct{ sec atomic.Int64 }

func newClock(start int64) *fakeClock {
	c := &fakeClock{}
	c.sec.Store(start)
	return c
}
func (c *fakeClock) Now() time.Time     { return time.Unix(c.sec.Load(), 0) }
func (c *fakeClock) Advance(s int64)    { c.sec.Add(s) }
func (c *fakeClock) Set(s int64)        { c.sec.Store(s) }
func obs(r *Recorder, d int, lat int64) { r.Observe(Sample{Decision: d, LatencyUS: lat}) }

const t0 = int64(1_800_000_000) // кратно 60: удобно для минутных границ

func TestObserveCountsPerSecondAndTotals(t *testing.T) {
	c := newClock(t0)
	r := New(c.Now)
	for i := 0; i < 10; i++ {
		obs(r, Allow, 50)
	}
	obs(r, Review, 200)
	obs(r, Block, 300)
	r.Observe(Sample{Decision: Allow, Stage: StageML, LatencyUS: 8000, Emergency: false, Duplicate: true, RuleFloor: true, Suppressed: true})
	r.Observe(Sample{Decision: Allow, Emergency: true})
	r.ObserveError()

	tot := r.Totals()
	if tot.Allow != 12 || tot.Review != 1 || tot.Block != 1 || tot.ML != 1 || tot.Emergency != 1 || tot.Errors != 1 {
		t.Fatalf("totals = %+v", tot)
	}
	p := r.Window(10 * time.Second)
	if p.Total != 14 || p.Allow != 12 || p.Review != 1 || p.Block != 1 || p.ML != 1 || p.Duplicates != 1 || p.Floors != 1 || p.Emergency != 1 {
		t.Fatalf("window = %+v", p)
	}
}

func TestSeriesPlacesEventsInTheRightBuckets(t *testing.T) {
	c := newClock(t0)
	r := New(c.Now)
	for s := 0; s < 30; s++ {
		obs(r, Allow, 100)
		if s%10 == 0 {
			obs(r, Block, 100)
		}
		if s < 29 {
			c.Advance(1) // после последнего события время не двигаем: окно «последние 30 с» покрывает t0..t0+29
		}
	}
	pts := r.Series(30*time.Second, 3) // три точки по 10 секунд
	if len(pts) != 3 {
		t.Fatalf("points = %d", len(pts))
	}
	var allow, block uint64
	for _, p := range pts {
		allow += p.Allow
		block += p.Block
	}
	if allow != 30 || block != 3 {
		t.Fatalf("series sums: allow=%d block=%d, want 30/3; %+v", allow, block, pts)
	}
	for i, p := range pts {
		if p.Allow != 10 {
			t.Fatalf("point %d has %d allow, want 10 (events are evenly spaced): %+v", i, p.Allow, pts)
		}
		if i > 0 && p.T-pts[i-1].T != 10 {
			t.Fatalf("time step: %+v", pts)
		}
	}
	if pts[0].RPS <= 0 {
		t.Fatalf("rps must be positive: %+v", pts[0])
	}
}

func TestEmptyIntervalsAreZeroPointsNotGaps(t *testing.T) {
	c := newClock(t0)
	r := New(c.Now)
	obs(r, Allow, 10)
	c.Advance(100)
	pts := r.Series(120*time.Second, 12)
	if len(pts) != 12 {
		t.Fatalf("points = %d", len(pts))
	}
	var total uint64
	zero := 0
	for _, p := range pts {
		total += p.Total
		if p.Total == 0 {
			zero++
			if p.P99US != 0 || p.MeanUS != 0 {
				t.Fatalf("empty point must have zero latency: %+v", p)
			}
		}
	}
	if total != 1 || zero != 11 {
		t.Fatalf("total=%d zero=%d", total, zero)
	}
}

func TestRingSlotIsReusedAfterWrapAround(t *testing.T) {
	c := newClock(t0)
	r := New(c.Now)
	obs(r, Block, 10)
	c.Advance(secSlots) // ровно круг: тот же слот, другая секунда
	obs(r, Allow, 10)
	p := r.Window(5 * time.Second)
	if p.Allow != 1 || p.Block != 0 {
		t.Fatalf("stale bucket data must not leak after wrap-around: %+v", p)
	}
}

func TestMinuteFoldingAndLongWindow(t *testing.T) {
	c := newClock(t0)
	r := New(c.Now)
	// 30 минут по 5 вызовов в минуту (2 review)
	for m := 0; m < 30; m++ {
		for i := 0; i < 5; i++ {
			d := Allow
			if i < 2 {
				d = Review
			}
			obs(r, d, 1000)
		}
		c.Advance(60)
		r.Roll()
	}
	pts := r.Series(time.Hour, 60) // шаг 1 минута → из поминутного буфера
	var total, review uint64
	for _, p := range pts {
		total += p.Total
		review += p.Review
	}
	if total != 150 || review != 60 {
		t.Fatalf("long window totals: total=%d review=%d (want 150/60)", total, review)
	}
	// Короткое окно (10 минут, шаг ≥ 60 с — тоже из поминутного буфера) видит только свою треть событий.
	if p := r.Window(10 * time.Minute); p.Total < 40 || p.Total > 55 {
		t.Fatalf("10-minute window must hold about 9-10 minutes of events (5 per minute): %+v", p)
	}
	// Окно в 5 минут короче полного буфера секунд: берётся посекундно и тоже не выходит за свои границы.
	if p := r.Window(5 * time.Minute); p.Total < 20 || p.Total > 30 {
		t.Fatalf("5-minute window: %+v", p)
	}
}

func TestLongWindowIncludesUnfoldedCurrentMinute(t *testing.T) {
	c := newClock(t0)
	r := New(c.Now)
	for i := 0; i < 7; i++ {
		obs(r, Allow, 10)
	}
	c.Advance(20) // всё ещё в той же минуте: свёртка минутного буфера не завершена
	for i := 0; i < 3; i++ {
		obs(r, Review, 10)
	}
	pts := r.Series(time.Hour, 60)
	var total uint64
	for _, p := range pts {
		total += p.Total
	}
	if total != 10 {
		t.Fatalf("current unfolded minute must be visible in long windows, got %d", total)
	}
}

func TestRollIsIdempotentAndSurvivesLongIdle(t *testing.T) {
	c := newClock(t0)
	r := New(c.Now)
	obs(r, Allow, 10)
	c.Advance(2)
	r.Roll()
	r.Roll()
	r.Roll()
	m := &r.mins[(t0/60)%minSlots]
	if m.ts.Load() != t0 || m.decisions[Allow].Load() != 1 {
		t.Fatalf("repeated Roll must not double count: ts=%d allow=%d", m.ts.Load(), m.decisions[Allow].Load())
	}
	c.Advance(10 * 3600) // долгий простой дольше секундного буфера
	r.Roll()
	obs(r, Allow, 10)
	if p := r.Window(5 * time.Second); p.Allow != 1 {
		t.Fatalf("after a long idle the recorder must keep working: %+v", p)
	}
}

func TestPercentiles(t *testing.T) {
	var h [nLat]uint64
	if percentile(&h, 0.5) != 0 {
		t.Fatal("empty histogram")
	}
	// 100 значений по 40 мкс (корзина 25..50) и 1 по 30 мс (корзина 25000..50000)
	h[latIndex(40)] = 100
	h[latIndex(30000)] = 1
	if p50 := percentile(&h, 0.50); p50 < 25 || p50 > 50 {
		t.Fatalf("p50 = %v, want within 25..50", p50)
	}
	if p999 := percentile(&h, 0.999); p999 < 25000 || p999 > 50000 {
		t.Fatalf("p99.9 = %v, want within 25000..50000", p999)
	}
	if latIndex(0) != 0 || latIndex(25) != 0 || latIndex(26) != 1 || latIndex(1_000_000) != len(latBoundsUS) {
		t.Fatal("latIndex boundaries")
	}
	var over [nLat]uint64
	over[len(latBoundsUS)] = 5 // всё в последней корзине
	if p := percentile(&over, 0.5); p <= float64(latBoundsUS[len(latBoundsUS)-1]) {
		t.Fatalf("overflow bucket percentile = %v", p)
	}
}

func TestLatencyPercentilesInPoint(t *testing.T) {
	c := newClock(t0)
	r := New(c.Now)
	for i := 0; i < 99; i++ {
		obs(r, Allow, 40)
	}
	obs(r, Allow, 20_000)
	p := r.Window(5 * time.Second)
	if p.P50US > 50 || p.P99US < 40 || p.P99US > 100_000 || math.Abs(p.MeanUS-(99*40+20000)/100.0) > 1e-9 {
		t.Fatalf("latency stats: %+v", p)
	}
}

func TestRecentEventsNewestFirstFilteredAndBounded(t *testing.T) {
	r := New(newClock(t0).Now)
	for i := 0; i < 1500; i++ { // больше ёмкости кольца
		d := "review"
		if i%3 == 0 {
			d = "block"
		}
		r.RecordEvent(Event{CallID: fmt.Sprint("c", i), Decision: d})
	}
	all := r.Recent(5, "")
	if len(all) != 5 || all[0].CallID != "c1499" || all[4].CallID != "c1495" {
		t.Fatalf("newest first: %+v", all)
	}
	blocks := r.Recent(10, "block")
	if len(blocks) != 10 {
		t.Fatalf("filter: %d", len(blocks))
	}
	for _, e := range blocks {
		if e.Decision != "block" {
			t.Fatalf("filter leaked %+v", e)
		}
	}
	if got := r.Recent(1_000_000, ""); len(got) != 100 {
		t.Fatalf("absurd limit falls back to default, got %d", len(got))
	}
	if got := r.Recent(0, ""); len(got) != 100 {
		t.Fatalf("zero limit falls back to default, got %d", len(got))
	}
	// в кольце не больше 1000 последних: c0..c499 вытеснены
	if got := r.Recent(1000, ""); len(got) != 1000 || got[999].CallID != "c500" {
		t.Fatalf("ring keeps the last 1000: len=%d last=%v", len(got), got[len(got)-1].CallID)
	}
}

func TestTopFactorsAndSignals(t *testing.T) {
	r := New(newClock(t0).Now)
	mk := func(sig []string, factors ...string) Event {
		ev := Event{Signals: sig}
		for _, f := range factors {
			ev.Reasons = append(ev.Reasons, Reason{Factor: f, Effect: "raises"})
		}
		ev.Reasons = append(ev.Reasons, Reason{Factor: "call_duration", Effect: "lowers"}) // смягчающие не считаются
		return ev
	}
	r.RecordEvent(mk([]string{"spoof"}, "spoof", "foreign_ingress"))
	r.RecordEvent(mk([]string{"spoof", "burst"}, "spoof", "out_short_share"))
	r.RecordEvent(mk(nil, "spoof"))
	f := r.TopFactors(2)
	if len(f) != 2 || f[0].Name != "spoof" || f[0].Count != 3 {
		t.Fatalf("factors = %+v", f)
	}
	for _, c := range r.TopFactors(0) {
		if c.Name == "call_duration" {
			t.Fatal("mitigating factors must not be counted")
		}
	}
	s := r.TopSignals(10)
	if len(s) != 2 || s[0].Name != "spoof" || s[0].Count != 2 || s[1].Name != "burst" {
		t.Fatalf("signals = %+v", s)
	}
}

func TestInvalidDecisionIsClampedNotPanic(t *testing.T) {
	r := New(newClock(t0).Now)
	r.Observe(Sample{Decision: 99, Stage: 99, LatencyUS: -5})
	r.Observe(Sample{Decision: -1})
	if r.Totals().Allow != 2 {
		t.Fatalf("invalid decisions count as allow: %+v", r.Totals())
	}
}

func TestConcurrentObserveAndRead(t *testing.T) {
	c := newClock(t0)
	r := New(c.Now)
	stop := make(chan struct{})
	go r.Run(stop)
	defer close(stop)
	var wg sync.WaitGroup
	const per = 20_000
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				r.Observe(Sample{Decision: i % 3, Stage: i % 2, LatencyUS: int64(i % 5000)})
				if i%5000 == 0 {
					r.RecordEvent(Event{CallID: "x", Decision: "review", Reasons: []Reason{{Factor: "f", Effect: "raises"}}})
					_ = r.Series(time.Minute, 30)
					_ = r.Recent(10, "")
					_ = r.TopFactors(3)
				}
			}
		}(g)
	}
	wg.Wait()
	tot := r.Totals()
	if got := tot.Allow + tot.Review + tot.Block; got != 8*per {
		t.Fatalf("lost updates: %d of %d", got, 8*per)
	}
}

func TestStartedAndDefaultClock(t *testing.T) {
	r := New(nil)
	if time.Since(r.Started()) > time.Minute {
		t.Fatal("Started must be recent")
	}
	r.Observe(Sample{})
	if r.Totals().Allow != 1 {
		t.Fatal("default clock works")
	}
}

func BenchmarkObserveParallel(b *testing.B) {
	r := New(nil)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			r.Observe(Sample{Decision: i % 3, Stage: i % 2, LatencyUS: int64(i % 3000)})
		}
	})
}
