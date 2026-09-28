package graph

import "sync"

const (
	subShards     = 64
	maxNumsPerSub = 64
)

// Subscribers считает, сколько разных номеров принадлежит одному абоненту (по subscriber_id
// из данных оператора). Много номеров у одного абонента — признак фермы SIM-карт.
// Память ограничена: до 64 номеров на абонента, число абонентов — до maxSubs на шард.
type Subscribers struct {
	maxPerShard int
	shards      [subShards]struct {
		mu sync.Mutex
		m  map[uint64][]uint64
	}
}

// NewSubscribers создаёт счётчик; maxSubs — общий предел абонентов (0 → 2 млн).
func NewSubscribers(maxSubs int) *Subscribers {
	if maxSubs <= 0 {
		maxSubs = 2_000_000
	}
	s := &Subscribers{maxPerShard: maxSubs/subShards + 1}
	for i := range s.shards {
		s.shards[i].m = make(map[uint64][]uint64)
	}
	return s
}

// Observe регистрирует связь абонент↔номер и возвращает число известных номеров абонента.
// sub == 0 означает «абонент неизвестен» → 0.
func (s *Subscribers) Observe(sub, number uint64) int {
	if sub == 0 {
		return 0
	}
	sh := &s.shards[(sub*0x9E3779B97F4A7C15)>>58]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	nums, ok := sh.m[sub]
	if !ok && len(sh.m) >= s.maxPerShard {
		for k := range sh.m {
			delete(sh.m, k)
			break
		}
	}
	for _, n := range nums {
		if n == number {
			return len(nums)
		}
	}
	if len(nums) < maxNumsPerSub {
		nums = append(nums, number)
		sh.m[sub] = nums
	}
	return len(nums)
}

// Count возвращает число известных номеров абонента.
func (s *Subscribers) Count(sub uint64) int {
	if sub == 0 {
		return 0
	}
	sh := &s.shards[(sub*0x9E3779B97F4A7C15)>>58]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return len(sh.m[sub])
}
