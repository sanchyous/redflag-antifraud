package window

import (
	"math"
	"math/rand/v2"
	"sync"
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/callrec"
)

const t0 = int64(1_800_000_000)

func ev(caller, callee uint64, ts int64, dur uint32, answered bool, callerReg, calleeReg uint16) *callrec.Event {
	var fl uint16
	if answered {
		fl |= callrec.FlagAnswered
	}
	return &callrec.Event{TS: ts, Caller: caller, Callee: callee, DurSec: dur, CallerRegion: callerReg, CalleeRegion: calleeReg, Flags: fl}
}

func near(a, b float32) bool { return math.Abs(float64(a-b)) < 1e-4 }

func TestWindowBoundaries(t *testing.T) {
	s := New(Config{})
	const c = 1
	// вызовы за 86399 с, 3600 с, 3599 с и 0 с до момента now=t0
	for i, off := range []int64{86399, 3600, 3599, 0} {
		s.Observe(ev(c, uint64(100+i), t0-off, 30, true, 0, 0))
	}
	f := s.Peek(c, true, t0)
	if f.Calls24h != 4 {
		t.Fatalf("Calls24h = %d, want 4", f.Calls24h)
	}
	if f.Calls1h != 2 {
		t.Fatalf("Calls1h = %d, want 2 (3599 и 0; ровно 3600 уже вне окна)", f.Calls1h)
	}
	// на секунду позже: вызов 86399 выпадает из суток
	if f = s.Peek(c, true, t0+1); f.Calls24h != 3 {
		t.Fatalf("Calls24h at +1s = %d, want 3", f.Calls24h)
	}
}

func TestUniquePeersAndRepeat(t *testing.T) {
	s := New(Config{})
	for i := 0; i < 10; i++ {
		s.Observe(ev(1, uint64(200+i%3), t0+int64(i), 30, true, 0, 0)) // 3 разных получателя
	}
	f := s.Peek(1, true, t0+10)
	if f.Calls1h != 10 || f.Peers1h != 3 || f.Peers24h != 3 {
		t.Fatalf("%+v", f)
	}
}

func TestDistinctLargeMatchesBruteForce(t *testing.T) {
	var tbl [1024]uint64
	r := rand.New(rand.NewPCG(1, 2))
	for _, n := range []int{0, 1, 2, 24, 25, 100, 512} {
		vals := make([]uint64, n)
		seen := map[uint64]struct{}{}
		for i := range vals {
			vals[i] = r.Uint64N(200) // много повторов, включая 0
			seen[vals[i]] = struct{}{}
		}
		if got := distinct(vals, &tbl); got != len(seen) {
			t.Fatalf("n=%d distinct=%d want %d", n, got, len(seen))
		}
	}
}

func TestRegionsAndEntropy(t *testing.T) {
	s := New(Config{})
	// 4 вызова: 2 в регион 5, 2 в регион 7 → 2 региона, энтропия 1 бит
	for i, reg := range []uint16{5, 5, 7, 7} {
		s.Observe(ev(1, uint64(300+i), t0+int64(i), 30, true, 0, reg))
	}
	f := s.Peek(1, true, t0+5)
	if f.Regions24h != 2 || !near(f.RegionEntropy, 1) {
		t.Fatalf("regions=%d entropy=%v", f.Regions24h, f.RegionEntropy)
	}
	// неизвестный регион (0) не считается регионом
	s2 := New(Config{})
	s2.Observe(ev(1, 9, t0, 30, true, 0, 0))
	if f := s2.Peek(1, true, t0); f.Regions24h != 0 || f.RegionEntropy != 0 {
		t.Fatalf("unknown region counted: %+v", f)
	}
}

func TestSharesShortAndUnanswered(t *testing.T) {
	s := New(Config{ShortSec: 10})
	// 4 принятых: 3 коротких (<10 с), 1 длинный; плюс 4 неотвеченных
	for i, d := range []uint32{2, 5, 9, 60} {
		s.Observe(ev(1, uint64(400+i), t0+int64(i), d, true, 0, 0))
	}
	for i := 0; i < 4; i++ {
		s.Observe(ev(1, uint64(500+i), t0+int64(10+i), 0, false, 0, 0))
	}
	f := s.Peek(1, true, t0+20)
	if !near(f.ShortShare, 0.75) || !near(f.UnansweredShare, 0.5) {
		t.Fatalf("short=%v unanswered=%v", f.ShortShare, f.UnansweredShare)
	}
	// ровно порог не «короткий»
	s2 := New(Config{ShortSec: 10})
	s2.Observe(ev(1, 2, t0, 10, true, 0, 0))
	if f := s2.Peek(1, true, t0); f.ShortShare != 0 {
		t.Fatalf("10 s must not be short: %v", f.ShortShare)
	}
}

func TestGapRegularity(t *testing.T) {
	s := New(Config{})
	for i := 0; i < 20; i++ { // робот: строго каждые 30 с
		s.Observe(ev(1, uint64(600+i), t0+int64(i*30), 3, true, 0, 0))
	}
	f := s.Peek(1, true, t0+600)
	if !near(f.GapMeanSec, 30) || f.GapCV > 1e-3 {
		t.Fatalf("robot: mean=%v cv=%v", f.GapMeanSec, f.GapCV)
	}
	// человек: нерегулярно
	h := New(Config{})
	r := rand.New(rand.NewPCG(7, 7))
	ts := t0
	for i := 0; i < 20; i++ {
		ts += 1 + int64(r.ExpFloat64()*60)
		h.Observe(ev(2, uint64(700+i), ts, 40, true, 0, 0))
	}
	if f := h.Peek(2, true, ts); f.GapCV < 0.4 {
		t.Fatalf("human cv too regular: %v", f.GapCV)
	}
	// меньше трёх вызовов — интервалов нет
	if f := New(Config{}).Peek(1, true, t0); f.GapMeanSec != 0 {
		t.Fatal("no data must give zero")
	}
}

func TestInboundSideSeparate(t *testing.T) {
	s := New(Config{})
	var last Features
	for i := 0; i < 5; i++ { // на номер 900 звонят 5 разных
		last = s.Observe(ev(uint64(800+i), 900, t0+int64(i), 0, false, 0, 0))
	}
	if last.In.Calls1h != 5 || last.In.Peers1h != 5 || !near(last.In.UnansweredShare, 1) {
		t.Fatalf("In = %+v", last.In)
	}
	if last.Out.Calls1h != 1 {
		t.Fatalf("Out of the last caller = %+v", last.Out)
	}
	// у номера 900 нет исходящих
	if f := s.Peek(900, true, t0+10); f.Calls24h != 0 {
		t.Fatalf("callee has phantom outbound: %+v", f)
	}
}

func TestOutOfOrderAndFutureEvents(t *testing.T) {
	s := New(Config{})
	s.Observe(ev(1, 2, t0+100, 30, true, 0, 0))
	f := s.Observe(ev(1, 3, t0, 30, true, 0, 0)) // запоздавшее событие
	if f.Out.Calls1h != 1 {
		t.Fatalf("future entry must be ignored at now=t0: %+v", f.Out)
	}
	if f := s.Peek(1, true, t0+100); f.Calls1h != 2 {
		t.Fatalf("at now=t0+100 both counted: %+v", f)
	}
}

func TestSaturationExtrapolates(t *testing.T) {
	s := New(Config{MaxEvents: 64})
	// 200 вызовов за 100 секунд → буфер (64) покрывает лишь часть; частота оценивается по размаху
	var f Features
	for i := 0; i < 200; i++ {
		f = s.Observe(ev(1, uint64(1000+i), t0+int64(i/2), 3, true, 0, 0))
	}
	if !f.Out.Saturated {
		t.Fatal("expected saturation")
	}
	// реальная частота 2 вызова/с → ~7200 в час; допускаем разумный разброс оценки
	if f.Out.Calls1h < 5000 || f.Out.Calls1h > 9000 {
		t.Fatalf("Calls1h estimate = %d", f.Out.Calls1h)
	}
	if f.Out.Calls24h < f.Out.Calls1h {
		t.Fatalf("24h < 1h: %+v", f.Out)
	}
}

func TestSweepAndEviction(t *testing.T) {
	s := New(Config{})
	s.Observe(ev(1, 2, t0, 3, true, 0, 0))
	s.Observe(ev(3, 4, t0+day-10, 3, true, 0, 0))
	if s.Len() != 4 {
		t.Fatalf("Len = %d", s.Len())
	}
	if n := s.Sweep(t0 + day + 5); n != 2 { // 1 и 2 простаивают > суток
		t.Fatalf("Sweep removed %d", n)
	}
	if s.Len() != 2 {
		t.Fatalf("Len after sweep = %d", s.Len())
	}
	if s.Sweep(5) != 0 {
		t.Fatal("early time must not sweep")
	}
	// вытеснение при переполнении
	small := New(Config{MaxNumbers: 256}) // 2 номера на шард
	for i := 0; i < 5000; i++ {
		small.Observe(ev(uint64(i), uint64(1_000_000+i), t0, 3, true, 0, 0))
	}
	if small.Len() > 256*2+256 {
		t.Fatalf("eviction failed, Len = %d", small.Len())
	}
}

func TestConcurrentObserve(t *testing.T) {
	s := New(Config{})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				s.Observe(ev(uint64(i%50), uint64(1000+g), t0+int64(i), 5, i%3 != 0, 1, 2))
				s.Peek(uint64(i%50), true, t0+int64(i))
			}
		}(g)
	}
	wg.Wait()
	if f := s.Peek(7, true, t0+2000); f.Calls24h == 0 {
		t.Fatal("no data after concurrent writes")
	}
}

func TestDedupe(t *testing.T) {
	d := NewDedupe(100)
	if d.Seen("a", 1000) || !d.Seen("a", 1050) {
		t.Fatal("first must be new, second duplicate")
	}
	if d.Seen("b", 1000) {
		t.Fatal("different id must be new")
	}
	if d.Seen("a", 1100) { // истёк TTL → снова новый
		t.Fatal("expired id must be accepted again")
	}
	if n := d.Sweep(1300); n != 2 || d.Len() != 0 {
		t.Fatalf("sweep removed %d, len %d", n, d.Len())
	}
	if NewDedupe(0).ttl != day {
		t.Fatal("default ttl must be 24h")
	}
}

func BenchmarkObserveParallel(b *testing.B) {
	s := New(Config{})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewPCG(rand.Uint64(), 1))
		i := int64(0)
		for pb.Next() {
			i++
			s.Observe(ev(r.Uint64N(1_000_000), r.Uint64N(1_000_000), t0+i, uint32(r.IntN(120)), r.IntN(3) != 0, uint16(r.IntN(90)), uint16(r.IntN(90))))
		}
	})
}

func BenchmarkObserveHeavyNumber(b *testing.B) {
	s := New(Config{})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Observe(ev(1, uint64(i), t0+int64(i/3), 3, true, uint16(i%90), 5))
	}
}

func TestProfiles(t *testing.T) {
	s := New(Config{})
	for i := 0; i < 12; i++ { // номер 1: 12 вызовов на 12 разных, 3 с, каждые 10 с, из-за рубежа
		e := ev(1, uint64(100+i), t0+int64(i*10), 3, true, 0, 0)
		e.Flags |= callrec.FlagForeignIngress
		s.Observe(e)
	}
	for i := 0; i < 3; i++ { // номер 2: слишком мало вызовов
		s.Observe(ev(2, uint64(900+i), t0+int64(i), 3, true, 0, 0))
	}
	s.Observe(ev(3, 1, t0-5000, 3, true, 0, 0)) // старый вызов вне периода
	ps := s.Profiles(t0+200, 3600, 10)
	if len(ps) != 1 || ps[0].Key != 1 {
		t.Fatalf("profiles = %+v", ps)
	}
	p := ps[0]
	if p.Calls != 12 || len(p.Peers) != 12 || !near(p.MeanDurSec, 3) || !near(p.GapMeanSec, 10) ||
		!near(p.ForeignShare, 1) || p.UnansweredShr != 0 {
		t.Fatalf("profile = %+v", p)
	}
}
