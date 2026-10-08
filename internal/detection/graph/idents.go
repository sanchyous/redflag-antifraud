package graph

import "sync"

const (
	identShards    = 64
	maxImsiPerNum  = 32
	defaultMaxNums = 2_000_000
)

// Idents считает, сколько разных IMSI замечено на одном и том же номере (Caller). Легитимная
// смена телефона время от времени — нормально, но несколько IMSI за короткое окно, особенно
// пересекающихся по времени, — признак клонирования SIM или подмены модуля идентификации (S4).
// Устройство идентично Subscribers (internal/detection/graph/subscribers.go), но ключ и смысл
// обратные: там номер→абонент, здесь номер→набор IMSI.
type Idents struct {
	maxPerShard int
	shards      [identShards]struct {
		mu sync.Mutex
		m  map[uint64][]uint64
	}
}

// NewIdents создаёт счётчик; maxNums — общий предел номеров (0 → 2 млн).
func NewIdents(maxNums int) *Idents {
	if maxNums <= 0 {
		maxNums = defaultMaxNums
	}
	s := &Idents{maxPerShard: maxNums/identShards + 1}
	for i := range s.shards {
		s.shards[i].m = make(map[uint64][]uint64)
	}
	return s
}

// Observe регистрирует связь номер↔IMSI и возвращает число разных IMSI, замеченных на номере.
// imsi == 0 означает «IMSI неизвестен» → наблюдение не засчитывается, возвращается уже известное число.
func (s *Idents) Observe(number, imsi uint64) int {
	sh := &s.shards[(number*0x9E3779B97F4A7C15)>>58]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	imsis, ok := sh.m[number]
	if imsi == 0 {
		return len(imsis)
	}
	if !ok && len(sh.m) >= s.maxPerShard {
		for k := range sh.m {
			delete(sh.m, k)
			break
		}
	}
	for _, v := range imsis {
		if v == imsi {
			return len(imsis)
		}
	}
	if len(imsis) < maxImsiPerNum {
		imsis = append(imsis, imsi)
		sh.m[number] = imsis
	}
	return len(imsis)
}

// Count возвращает число известных IMSI номера.
func (s *Idents) Count(number uint64) int {
	sh := &s.shards[(number*0x9E3779B97F4A7C15)>>58]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return len(sh.m[number])
}
