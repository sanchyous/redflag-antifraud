package api

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter — грубый ограничитель частоты запросов по ключу (API-ключ, иначе IP): фиксированное окно
// в секунду, атомарный счётчик на ключ, тот же принцип, что у logx.RateLimit для логов. Не token bucket —
// осознанно проще: этого достаточно, чтобы один клиент не мог забрать всю пропускную способность ядра
// или нагрузить ML-сервис, а не для точного шейпинга трафика. Без внешних зависимостей (Redis и т.п.) —
// согласуется с ADR-0009: состояние живёт в памяти процесса, как и окна по номерам.
type RateLimiter struct {
	perSecond int64
	mu        sync.RWMutex
	buckets   map[string]*rlBucket
	now       func() int64 // подменяется в тестах
}

type rlBucket struct {
	sec   atomic.Int64
	count atomic.Int64
}

// NewRateLimiter создаёт ограничитель. perSecond <= 0 — ограничитель выключен, Allow/AllowN всегда true.
func NewRateLimiter(perSecond int) *RateLimiter {
	return &RateLimiter{perSecond: int64(perSecond), buckets: map[string]*rlBucket{}, now: func() int64 { return time.Now().Unix() }}
}

// Enabled сообщает, включено ли ограничение (для /v1/status и логов конфигурации).
func (l *RateLimiter) Enabled() bool { return l != nil && l.perSecond > 0 }

func (l *RateLimiter) bucketFor(key string) *rlBucket {
	l.mu.RLock()
	b := l.buckets[key]
	l.mu.RUnlock()
	if b != nil {
		return b
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if b = l.buckets[key]; b == nil {
		b = &rlBucket{}
		l.buckets[key] = b
	}
	return b
}

// AllowN сообщает, можно ли пропустить n единиц по данному ключу в текущую секунду, и сразу их засчитывает.
func (l *RateLimiter) AllowN(key string, n int64) bool {
	if l == nil || l.perSecond <= 0 {
		return true
	}
	b := l.bucketFor(key)
	now := l.now()
	if prev := b.sec.Load(); prev != now && b.sec.CompareAndSwap(prev, now) {
		b.count.Store(0)
	}
	return b.count.Add(n) <= l.perSecond
}

// rateLimit — middleware поверх уже прошедших auth (s.protect) запросов: ключ — X-API-Key, если auth
// включён, иначе IP. Применяется только к дорогим путям (скоринг), не к дашборду/метрикам/health.
// Пакетный запрос (/score/batch) считается за 1 — число вызовов в пакете неизвестно до разбора тела,
// а разбирать его дважды ради лимита дороже, чем того стоит; защита от крупных пакетов — maxBatchCalls.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	if !s.limiter.Enabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = remoteIP(r)
		}
		if !s.limiter.AllowN(key, 1) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
