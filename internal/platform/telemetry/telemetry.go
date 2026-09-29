// Package telemetry — метрики для панели мониторинга: скользящие временные ряды в памяти процесса
// (без внешней БД и без зависимостей), последние события рискованных решений и счётчики причин.
//
// Цена на горячем пути — одна запись в секундный кольцевой буфер атомарными операциями (~10 атомарных сложений,
// без блокировок и аллокаций). Минутный буфер (сутки истории) заполняется фоном: раз в секунду завершённые секунды
// сворачиваются в минуты (Roll). Оба буфера отдают ряды для графиков: решения по типам, доля ML, перцентили задержки.
package telemetry

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Решения (порядок — как в decide.Verdict).
const (
	Allow = iota
	Review
	Block
	nDecisions
)

// Стадии решения.
const (
	StageLinear = iota
	StageML
	nStages
)

// latBoundsUS — верхние границы корзин гистограммы задержки, микросекунды; последняя корзина — «больше».
var latBoundsUS = [...]int64{25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000}

const nLat = len(latBoundsUS) + 1

const (
	secSlots = 900  // 15 минут посекундно
	minSlots = 1440 // 24 часа поминутно
)

// Sample — итог одного скоринга для телеметрии.
type Sample struct {
	Decision   int
	Stage      int
	LatencyUS  int64
	Emergency  bool
	Duplicate  bool
	RuleFloor  bool
	Suppressed bool
}

type bucket struct {
	ts         atomic.Int64 // начало интервала, unix-секунды; 0 — слот не использован
	decisions  [nDecisions]atomic.Uint64
	stages     [nStages]atomic.Uint64
	emergency  atomic.Uint64
	duplicates atomic.Uint64
	floors     atomic.Uint64
	suppressed atomic.Uint64
	latSumUS   atomic.Uint64
	lat        [nLat]atomic.Uint64
}

func (b *bucket) reset(ts int64) {
	for i := range b.decisions {
		b.decisions[i].Store(0)
	}
	for i := range b.stages {
		b.stages[i].Store(0)
	}
	b.emergency.Store(0)
	b.duplicates.Store(0)
	b.floors.Store(0)
	b.suppressed.Store(0)
	b.latSumUS.Store(0)
	for i := range b.lat {
		b.lat[i].Store(0)
	}
	b.ts.Store(ts)
}

// addFrom прибавляет к b содержимое src (свёртка секунд в минуты).
func (b *bucket) addFrom(src *bucket) {
	for i := range b.decisions {
		b.decisions[i].Add(src.decisions[i].Load())
	}
	for i := range b.stages {
		b.stages[i].Add(src.stages[i].Load())
	}
	b.emergency.Add(src.emergency.Load())
	b.duplicates.Add(src.duplicates.Load())
	b.floors.Add(src.floors.Load())
	b.suppressed.Add(src.suppressed.Load())
	b.latSumUS.Add(src.latSumUS.Load())
	for i := range b.lat {
		b.lat[i].Add(src.lat[i].Load())
	}
}

func latIndex(us int64) int {
	i := 0
	for i < len(latBoundsUS) && us > latBoundsUS[i] {
		i++
	}
	return i
}

// Recorder — приёмник телеметрии. Безопасен для конкурентного использования.
type Recorder struct {
	now     func() time.Time
	started time.Time
	secs    [secSlots]bucket
	mins    [minSlots]bucket

	rollMu    sync.Mutex
	foldedSec int64 // последняя секунда, свёрнутая в минутный буфер

	total struct {
		decisions [nDecisions]atomic.Uint64
		stages    [nStages]atomic.Uint64
		emergency atomic.Uint64
		errors    atomic.Uint64
	}

	events  eventRing
	factors factorCounter
}

// New создаёт рекордер; now == nil — time.Now.
func New(now func() time.Time) *Recorder {
	if now == nil {
		now = time.Now
	}
	r := &Recorder{now: now, started: now()}
	r.events.init(1000)
	r.factors.m = map[string]uint64{}
	r.foldedSec = r.started.Unix() - 1
	return r
}

// Started — момент запуска (для uptime).
func (r *Recorder) Started() time.Time { return r.started }

// Observe записывает итог скоринга. Без блокировок и аллокаций.
func (r *Recorder) Observe(s Sample) {
	if s.Decision < 0 || s.Decision >= nDecisions {
		s.Decision = Allow
	}
	now := r.now().Unix()
	b := &r.secs[now%secSlots]
	if old := b.ts.Load(); old != now {
		// слот принадлежит прошлому кругу: первым, кто увидел это, сбрасывает его
		if b.ts.CompareAndSwap(old, now) {
			b.reset(now)
		}
	}
	b.decisions[s.Decision].Add(1)
	if s.Stage >= 0 && s.Stage < nStages {
		b.stages[s.Stage].Add(1)
		r.total.stages[s.Stage].Add(1)
	}
	if s.Emergency {
		b.emergency.Add(1)
		r.total.emergency.Add(1)
	}
	if s.Duplicate {
		b.duplicates.Add(1)
	}
	if s.RuleFloor {
		b.floors.Add(1)
	}
	if s.Suppressed {
		b.suppressed.Add(1)
	}
	if s.LatencyUS > 0 {
		b.latSumUS.Add(uint64(s.LatencyUS))
	}
	b.lat[latIndex(s.LatencyUS)].Add(1)
	r.total.decisions[s.Decision].Add(1)
}

// ObserveError считает ошибку контракта (400) — вызов не получил решения.
func (r *Recorder) ObserveError() { r.total.errors.Add(1) }

// Roll сворачивает завершённые секунды в минутный буфер. Вызывается фоном раз в секунду и лениво перед чтением.
func (r *Recorder) Roll() {
	r.rollMu.Lock()
	defer r.rollMu.Unlock()
	cur := r.now().Unix()
	from := r.foldedSec + 1
	if cur-from > secSlots { // долгий простой: старее буфера ничего нет
		from = cur - secSlots + 1
	}
	for sec := from; sec < cur; sec++ { // текущая (неполная) секунда не сворачивается
		sb := &r.secs[sec%secSlots]
		if sb.ts.Load() != sec {
			continue // в эту секунду вызовов не было
		}
		minute := sec - sec%60
		mb := &r.mins[(minute/60)%minSlots]
		if mb.ts.Load() != minute {
			mb.reset(minute)
		}
		mb.addFrom(sb)
	}
	if cur-1 > r.foldedSec {
		r.foldedSec = cur - 1
	}
}

// Run запускает фоновую свёртку до закрытия stop.
func (r *Recorder) Run(stop <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			r.Roll()
		}
	}
}

// Totals — суммарные счётчики с момента запуска.
type Totals struct {
	Allow, Review, Block uint64
	Linear, ML           uint64
	Emergency, Errors    uint64
}

// Totals возвращает счётчики с момента запуска.
func (r *Recorder) Totals() Totals {
	return Totals{
		Allow: r.total.decisions[Allow].Load(), Review: r.total.decisions[Review].Load(), Block: r.total.decisions[Block].Load(),
		Linear: r.total.stages[StageLinear].Load(), ML: r.total.stages[StageML].Load(),
		Emergency: r.total.emergency.Load(), Errors: r.total.errors.Load(),
	}
}

// Point — одна точка ряда.
type Point struct {
	T          int64   `json:"t"` // начало интервала, unix-секунды
	Allow      uint64  `json:"allow"`
	Review     uint64  `json:"review"`
	Block      uint64  `json:"block"`
	Total      uint64  `json:"total"`
	ML         uint64  `json:"ml"`
	Emergency  uint64  `json:"emergency"`
	Duplicates uint64  `json:"duplicates"`
	Floors     uint64  `json:"floors"`
	RPS        float64 `json:"rps"`
	P50US      float64 `json:"p50_us"`
	P95US      float64 `json:"p95_us"`
	P99US      float64 `json:"p99_us"`
	MeanUS     float64 `json:"mean_us"`
}

type accum struct {
	dec       [nDecisions]uint64
	stage     [nStages]uint64
	emergency uint64
	dup       uint64
	floors    uint64
	suppr     uint64
	latSum    uint64
	lat       [nLat]uint64
}

func (a *accum) add(b *bucket) {
	for i := range a.dec {
		a.dec[i] += b.decisions[i].Load()
	}
	for i := range a.stage {
		a.stage[i] += b.stages[i].Load()
	}
	a.emergency += b.emergency.Load()
	a.dup += b.duplicates.Load()
	a.floors += b.floors.Load()
	a.suppr += b.suppressed.Load()
	a.latSum += b.latSumUS.Load()
	for i := range a.lat {
		a.lat[i] += b.lat[i].Load()
	}
}

func (a *accum) total() uint64 { return a.dec[Allow] + a.dec[Review] + a.dec[Block] }

func (a *accum) point(t int64, stepSec float64) Point {
	n := a.total()
	p := Point{T: t, Allow: a.dec[Allow], Review: a.dec[Review], Block: a.dec[Block], Total: n, ML: a.stage[StageML],
		Emergency: a.emergency, Duplicates: a.dup, Floors: a.floors, RPS: float64(n) / stepSec}
	if n > 0 {
		p.P50US, p.P95US, p.P99US = percentile(&a.lat, 0.50), percentile(&a.lat, 0.95), percentile(&a.lat, 0.99)
		p.MeanUS = float64(a.latSum) / float64(n)
	}
	return p
}

// percentile оценивает перцентиль по гистограмме линейной интерполяцией внутри корзины.
func percentile(h *[nLat]uint64, q float64) float64 {
	var total uint64
	for _, c := range h {
		total += c
	}
	if total == 0 {
		return 0
	}
	target := q * float64(total)
	var cum float64
	for i, c := range h {
		next := cum + float64(c)
		if next >= target && c > 0 {
			lo := 0.0
			if i > 0 {
				lo = float64(latBoundsUS[i-1])
			}
			hi := lo * 2
			if i < len(latBoundsUS) {
				hi = float64(latBoundsUS[i])
			} else if lo == 0 {
				hi = 1
			}
			return lo + (hi-lo)*(target-cum)/float64(c)
		}
		cum = next
	}
	return float64(latBoundsUS[len(latBoundsUS)-1])
}

// Series возвращает ряд за последние window, разбитый на points точек. Окна до 15 минут берутся из посекундного
// буфера, длиннее — из поминутного. Пустые интервалы возвращаются нулевыми точками (график без разрывов).
func (r *Recorder) Series(window time.Duration, points int) []Point {
	r.Roll()
	if points < 1 {
		points = 60
	}
	if window < time.Second {
		window = time.Minute
	}
	now := r.now().Unix()
	step := int64(window.Seconds()) / int64(points)
	if step < 1 {
		step = 1
	}
	useMin := step >= 60
	end := now + 1 // конец окна (не включительно): последняя секунда — текущая
	if useMin {
		step -= step % 60
		// Точки поминутного режима выравниваются по границам минут: иначе минутный слот попадал бы
		// сразу в две соседние точки и засчитывался дважды.
		end = now - now%60 + 60
	}
	folded := r.foldedSecSnapshot()
	start := end - step*int64(points)
	out := make([]Point, 0, points)
	for i := 0; i < points; i++ {
		t0 := start + int64(i)*step
		var a accum
		if useMin {
			for m := t0 - t0%60; m < t0+step; m += 60 {
				b := &r.mins[(m/60)%minSlots]
				if b.ts.Load() == m {
					a.add(b)
				}
			}
			// текущая неполная минута ещё не свёрнута: добавим её несвёрнутые секунды напрямую
			curMin := now - now%60
			if curMin >= t0 && curMin < t0+step {
				for s := curMin; s <= now; s++ {
					if b := &r.secs[s%secSlots]; b.ts.Load() == s && s > folded {
						a.add(b)
					}
				}
			}
		} else {
			for s := t0; s < t0+step; s++ {
				if b := &r.secs[s%secSlots]; b.ts.Load() == s {
					a.add(b)
				}
			}
		}
		out = append(out, a.point(t0, float64(step)))
	}
	return out
}

func (r *Recorder) foldedSecSnapshot() int64 {
	r.rollMu.Lock()
	defer r.rollMu.Unlock()
	return r.foldedSec
}

// Window суммирует последние d (для карточек «за 5 минут»/«за час»).
func (r *Recorder) Window(d time.Duration) Point {
	return r.Series(d, 1)[0]
}

// ---- события и причины ----

// Reason — краткая причина решения для панели.
type Reason struct {
	Factor       string  `json:"factor"`
	Text         string  `json:"text"`
	Contribution float64 `json:"contribution"`
	Effect       string  `json:"effect"`
}

// Event — рискованное решение (review или block) для списка «проблем».
type Event struct {
	Time         time.Time `json:"time"`
	CallID       string    `json:"call_id"`
	Decision     string    `json:"decision"`
	Score        float64   `json:"score"`
	Stage        string    `json:"stage"`
	Signals      []string  `json:"signals"`
	Caller       string    `json:"caller"`
	Callee       string    `json:"callee"`
	CallerRegion string    `json:"caller_region,omitempty"`
	CalleeRegion string    `json:"callee_region,omitempty"`
	Reasons      []Reason  `json:"reasons"`
	RuleFloor    bool      `json:"rule_floor,omitempty"`
	Suppressed   bool      `json:"block_suppressed,omitempty"`
	SafeClass    string    `json:"safe_class,omitempty"`
	LatencyUS    int64     `json:"latency_us"`
}

type eventRing struct {
	mu   sync.Mutex
	buf  []Event
	next int
	full bool
}

func (e *eventRing) init(n int) { e.buf = make([]Event, n) }

func (e *eventRing) add(ev Event) {
	e.mu.Lock()
	e.buf[e.next] = ev
	e.next++
	if e.next == len(e.buf) {
		e.next, e.full = 0, true
	}
	e.mu.Unlock()
}

// RecordEvent запоминает рискованное решение и учитывает причины, повысившие риск.
func (r *Recorder) RecordEvent(ev Event) {
	r.events.add(ev)
	r.factors.add(ev)
}

// Recent возвращает последние события (новые первыми); decision != "" фильтрует по вердикту.
func (r *Recorder) Recent(limit int, decision string) []Event {
	if limit < 1 || limit > len(r.events.buf) {
		limit = 100
	}
	r.events.mu.Lock()
	defer r.events.mu.Unlock()
	n := r.events.next
	if r.events.full {
		n = len(r.events.buf)
	}
	out := make([]Event, 0, limit)
	for i := 1; i <= n && len(out) < limit; i++ {
		idx := (r.events.next - i + len(r.events.buf)) % len(r.events.buf)
		if ev := r.events.buf[idx]; decision == "" || ev.Decision == decision {
			out = append(out, ev)
		}
	}
	return out
}

type factorCounter struct {
	mu      sync.Mutex
	m       map[string]uint64
	signals map[string]uint64
}

func (f *factorCounter) add(ev Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.signals == nil {
		f.signals = map[string]uint64{}
	}
	for _, rs := range ev.Reasons {
		if rs.Effect == "raises" {
			f.m[rs.Factor]++
		}
	}
	for _, s := range ev.Signals {
		f.signals[s]++
	}
}

// Counted — имя и число срабатываний.
type Counted struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

func top(m map[string]uint64, n int) []Counted {
	out := make([]Counted, 0, len(m))
	for k, v := range m {
		out = append(out, Counted{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// TopFactors — факторы, чаще всего повышавшие риск в рискованных решениях.
func (r *Recorder) TopFactors(n int) []Counted {
	r.factors.mu.Lock()
	defer r.factors.mu.Unlock()
	return top(r.factors.m, n)
}

// TopSignals — сильные сигналы, чаще всего сопровождавшие рискованные решения.
func (r *Recorder) TopSignals(n int) []Counted {
	r.factors.mu.Lock()
	defer r.factors.mu.Unlock()
	return top(r.factors.signals, n)
}
