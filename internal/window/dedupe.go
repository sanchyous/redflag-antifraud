package window

import "sync"

const dedupeShards = 64

// Dedupe — идемпотентность по call_id: повторная доставка одного вызова не должна дважды
// попадать в окна. Хранит 64-битный хэш идентификатора и время; записи старше TTL удаляются в Sweep.
type Dedupe struct {
	ttl    int64
	shards [dedupeShards]struct {
		mu sync.Mutex
		m  map[uint64]int64
	}
}

// NewDedupe создаёт набор с TTL в секундах (0 → 24 часа).
func NewDedupe(ttlSec int64) *Dedupe {
	if ttlSec <= 0 {
		ttlSec = day
	}
	d := &Dedupe{ttl: ttlSec}
	for i := range d.shards {
		d.shards[i].m = make(map[uint64]int64)
	}
	return d
}

func hashString(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// Seen возвращает true, если call_id уже встречался (и не истёк); иначе запоминает его.
func (d *Dedupe) Seen(callID string, now int64) bool {
	h := hashString(callID)
	sh := &d.shards[(h*0x9E3779B97F4A7C15)>>58]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if ts, ok := sh.m[h]; ok && now-ts < d.ttl {
		return true
	}
	sh.m[h] = now
	return false
}

// Sweep удаляет просроченные записи и возвращает их число.
func (d *Dedupe) Sweep(now int64) int {
	removed := 0
	for i := range d.shards {
		sh := &d.shards[i]
		sh.mu.Lock()
		for k, ts := range sh.m {
			if now-ts >= d.ttl {
				delete(sh.m, k)
				removed++
			}
		}
		sh.mu.Unlock()
	}
	return removed
}

// Len — число запомненных идентификаторов.
func (d *Dedupe) Len() int {
	n := 0
	for i := range d.shards {
		d.shards[i].mu.Lock()
		n += len(d.shards[i].m)
		d.shards[i].mu.Unlock()
	}
	return n
}
