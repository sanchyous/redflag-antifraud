// Package window — скользящие окна по номерам для горячего пути скоринга.
//
// Состояние живёт в памяти процесса, шардировано по ключу номера (256 шардов с
// мьютексами): обращение стоит порядка микросекунды, в отличие от сетевого похода в
// Redis. Для горизонтального масштабирования вызовы маршрутизируются по хэшу номера
// на инстанс (см. DECISIONS D-09).
//
// Окно считается по времени самого события, а не по часам сервера: онлайн-скоринг и
// обучение/оценка на исторических данных проходят через один и тот же код (нет
// рассинхрона признаков), а повторное проигрывание детерминировано.
package window

import (
	"math"
	"slices"
	"sync"

	"github.com/sanchyous/redflag-antifraud/internal/callrec"
)

const (
	shardCount = 256
	hour       = 3600
	day        = 24 * hour
	maxRegions = 256
)

// Config — параметры хранилища.
type Config struct {
	// MaxEvents — размер кольцевого буфера событий на номер (по умолчанию 512).
	MaxEvents int
	// MaxNumbers — верхняя граница числа отслеживаемых номеров (по умолчанию 4 млн).
	// При достижении в шарде вытесняется случайный номер.
	MaxNumbers int
	// ShortSec — принятый вызов короче этого порога считается коротким (по умолчанию 10).
	ShortSec int
}

func (c *Config) defaults() {
	if c.MaxEvents <= 0 {
		c.MaxEvents = 512
	}
	if c.MaxNumbers <= 0 {
		c.MaxNumbers = 4_000_000
	}
	if c.ShortSec <= 0 {
		c.ShortSec = 10
	}
}

// NumFeatures — признаки одного номера в одной роли (исходящие для звонящего,
// входящие для получателя) на момент события.
type NumFeatures struct {
	Calls1h, Calls24h uint32
	Peers1h, Peers24h uint32  // уникальные собеседники
	Regions24h        uint16  // уникальные регионы собеседников
	RegionEntropy     float32 // энтропия распределения регионов собеседников, бит
	ShortShare        float32 // доля коротких среди принятых (24 ч)
	UnansweredShare   float32 // доля неотвеченных (24 ч)
	GapMeanSec        float32 // средний интервал между вызовами за 1 ч (0 — мало данных)
	GapCV             float32 // коэффициент вариации интервалов за 1 ч (0 — мало данных)
	// Saturated — буфер номера переполнен: счётчики вызовов экстраполированы, уникальные — нижние оценки.
	Saturated bool
}

// Features — признаки обеих сторон вызова.
type Features struct {
	Out NumFeatures // звонящий как источник исходящих
	In  NumFeatures // получатель как приёмник входящих
}

const (
	fOut      uint8 = 1
	fAnswered uint8 = 2
)

type entry struct {
	peer   uint64
	ts     uint32
	dur    uint16
	region uint16
	flags  uint8
}

type state struct {
	ents []entry
	head int    // позиция записи, когда буфер полон
	last uint32 // ts последнего события (для вытеснения простаивающих)
}

type shard struct {
	mu sync.Mutex
	m  map[uint64]*state
}

// Store — хранилище окон. Безопасно для конкурентного использования.
type Store struct {
	cfg         Config
	shards      [shardCount]shard
	perShard    int
	scratchPool sync.Pool
}

type scratch struct {
	p24, p1 [512]uint64
	ts      [512]uint32
	tbl     [1024]uint64
}

// New создаёт хранилище.
func New(cfg Config) *Store {
	cfg.defaults()
	if cfg.MaxEvents > 512 {
		cfg.MaxEvents = 512 // ограничено размером scratch
	}
	s := &Store{cfg: cfg, perShard: cfg.MaxNumbers/shardCount + 1}
	for i := range s.shards {
		s.shards[i].m = make(map[uint64]*state)
	}
	s.scratchPool.New = func() any { return new(scratch) }
	return s
}

func (s *Store) shard(key uint64) *shard {
	// Мультипликативное перемешивание: номера различаются младшими цифрами.
	h := key * 0x9E3779B97F4A7C15
	return &s.shards[h>>56]
}

// Observe добавляет вызов в состояние обоих номеров и возвращает признаки обеих сторон
// на момент события (включая сам вызов). Не идемпотентно: дубли отсекайте Dedupe.
func (s *Store) Observe(ev *callrec.Event) Features {
	var f Features
	now := clampTS(ev.TS)
	answered := ev.Flags&callrec.FlagAnswered != 0
	dur := ev.DurSec
	if dur > math.MaxUint16 {
		dur = math.MaxUint16
	}
	sc := s.scratchPool.Get().(*scratch)

	outFlags := fOut
	inFlags := uint8(0)
	if answered {
		outFlags |= fAnswered
		inFlags |= fAnswered
	}
	f.Out = s.touch(ev.Caller, entry{peer: ev.Callee, ts: now, dur: uint16(dur), region: ev.CalleeRegion, flags: outFlags}, true, now, sc)
	f.In = s.touch(ev.Callee, entry{peer: ev.Caller, ts: now, dur: uint16(dur), region: ev.CallerRegion, flags: inFlags}, false, now, sc)
	s.scratchPool.Put(sc)
	return f
}

func clampTS(ts int64) uint32 {
	if ts < 0 {
		return 0
	}
	if ts > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(ts)
}

func (s *Store) touch(key uint64, e entry, out bool, now uint32, sc *scratch) NumFeatures {
	sh := s.shard(key)
	sh.mu.Lock()
	st := sh.m[key]
	if st == nil {
		if len(sh.m) >= s.perShard {
			for k := range sh.m { // случайное вытеснение: порядок обхода map не определён
				delete(sh.m, k)
				break
			}
		}
		st = &state{}
		sh.m[key] = st
	}
	if len(st.ents) < s.cfg.MaxEvents {
		st.ents = append(st.ents, e)
	} else {
		st.ents[st.head] = e
		st.head++
		if st.head == len(st.ents) {
			st.head = 0
		}
	}
	if now > st.last {
		st.last = now
	}
	nf := s.compute(st, out, now, sc)
	sh.mu.Unlock()
	return nf
}

// Peek возвращает признаки номера без добавления события (для чтения и тестов).
func (s *Store) Peek(key uint64, out bool, now int64) NumFeatures {
	sh := s.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	st := sh.m[key]
	if st == nil {
		return NumFeatures{}
	}
	sc := s.scratchPool.Get().(*scratch)
	nf := s.compute(st, out, clampTS(now), sc)
	s.scratchPool.Put(sc)
	return nf
}

// compute считает признаки по буферу. Вызывать под локом шарда.
func (s *Store) compute(st *state, out bool, now uint32, sc *scratch) NumFeatures {
	var (
		nf                     NumFeatures
		n1, n24                uint32
		k1, k24                int
		answered, short, unans uint32
		minTS                  = uint32(math.MaxUint32)
		regCnt                 [maxRegions]uint16
		regDistinct            int
		regTotal               uint32
		kts                    int
	)
	want := uint8(0)
	if out {
		want = fOut
	}
	for i := range st.ents {
		e := &st.ents[i]
		if e.flags&fOut != want || e.ts > now {
			continue
		}
		age := now - e.ts
		if age >= day {
			continue
		}
		if e.ts < minTS {
			minTS = e.ts
		}
		n24++
		sc.p24[k24] = e.peer
		k24++
		if e.flags&fAnswered != 0 {
			answered++
			if int(e.dur) < s.cfg.ShortSec {
				short++
			}
		} else {
			unans++
		}
		if e.region != 0 && e.region < maxRegions {
			if regCnt[e.region] == 0 {
				regDistinct++
			}
			regCnt[e.region]++
			regTotal++
		}
		if age < hour {
			n1++
			sc.p1[k1] = e.peer
			k1++
			sc.ts[kts] = e.ts
			kts++
		}
	}
	nf.Calls1h, nf.Calls24h = n1, n24
	nf.Peers24h = uint32(distinct(sc.p24[:k24], &sc.tbl))
	nf.Peers1h = uint32(distinct(sc.p1[:k1], &sc.tbl))
	nf.Regions24h = uint16(regDistinct)
	if regTotal > 0 && regDistinct > 1 {
		var h float64
		inv := 1 / float64(regTotal)
		for _, c := range regCnt {
			if c > 0 {
				p := float64(c) * inv
				h -= p * math.Log2(p)
			}
		}
		nf.RegionEntropy = float32(h)
	}
	if n24 > 0 {
		nf.UnansweredShare = float32(unans) / float32(n24)
	}
	if answered > 0 {
		nf.ShortShare = float32(short) / float32(answered)
	}
	if kts >= 3 {
		ts := sc.ts[:kts]
		slices.Sort(ts)
		var sum, sumSq float64
		gaps := float64(kts - 1)
		for i := 1; i < kts; i++ {
			g := float64(ts[i] - ts[i-1])
			sum += g
			sumSq += g * g
		}
		mean := sum / gaps
		nf.GapMeanSec = float32(mean)
		if mean > 0 {
			variance := sumSq/gaps - mean*mean
			if variance < 0 {
				variance = 0
			}
			nf.GapCV = float32(math.Sqrt(variance) / mean)
		}
	}
	// Буфер полон и охватывает меньше окна — считаем частоту по фактическому размаху.
	if len(st.ents) >= s.cfg.MaxEvents && n24 > 0 {
		nf.Saturated = true
		span := float64(now-minTS) + 1
		if span < day {
			nf.Calls24h = uint32(float64(n24) * day / span)
		}
		if span < hour {
			nf.Calls1h = uint32(float64(n24) * hour / span)
		}
	}
	return nf
}

// distinct считает уникальные значения: перебор для коротких списков, иначе хэш-таблица
// с открытой адресацией во временном буфере. Ключ хранится как key+1 (0 — пустая ячейка).
func distinct(vals []uint64, tbl *[1024]uint64) int {
	n := len(vals)
	if n <= 1 {
		return n
	}
	if n <= 24 {
		c := 0
	outer:
		for i := 0; i < n; i++ {
			for j := 0; j < i; j++ {
				if vals[j] == vals[i] {
					continue outer
				}
			}
			c++
		}
		return c
	}
	clear(tbl[:])
	c := 0
	for _, v := range vals {
		k := v + 1
		i := (v * 0x9E3779B97F4A7C15) >> 54 // 10 бит → 1024 ячейки
		for {
			cur := tbl[i]
			if cur == 0 {
				tbl[i] = k
				c++
				break
			}
			if cur == k {
				break
			}
			i = (i + 1) & 1023
		}
	}
	return c
}

// Len возвращает число отслеживаемых номеров.
func (s *Store) Len() int {
	n := 0
	for i := range s.shards {
		s.shards[i].mu.Lock()
		n += len(s.shards[i].m)
		s.shards[i].mu.Unlock()
	}
	return n
}

// Sweep удаляет номера без активности дольше суток. Возвращает число удалённых.
func (s *Store) Sweep(now int64) int {
	cut := clampTS(now)
	if cut < day {
		return 0
	}
	cut -= day
	removed := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for k, st := range sh.m {
			if st.last < cut {
				delete(sh.m, k)
				removed++
			}
		}
		sh.mu.Unlock()
	}
	return removed
}
