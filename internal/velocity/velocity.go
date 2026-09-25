// Package velocity — L2: частота действий в честном скользящем окне.
// ZSET + Lua: очистка старых событий, добавление, подсчёт и TTL — атомарно,
// граница окна не даёт «бесплатного» лимита, как у fixed window.
package velocity

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sanchyous/redflag-antifraud/internal/decision"
)

// slidingCheck — атомарная проверка одного счётчика.
// ARGV: now(ms), window(ms), max, уникальный member события.
var slidingCheck = redis.NewScript(`
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max    = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
redis.call('ZADD', key, now, member)
local n = redis.call('ZCARD', key)
redis.call('PEXPIRE', key, window)
return n
`)

// Limiter считает транзакции пользователя и IP в скользящем окне Window.
type Limiter struct {
	rdb        *redis.Client
	MaxPerUser int
	MaxPerIP   int
	Window     time.Duration
	// Now — источник времени; переопределяется в тестах.
	Now func() time.Time
}

func New(rdb *redis.Client, maxPerUser, maxPerIP int, window time.Duration) *Limiter {
	return &Limiter{rdb: rdb, MaxPerUser: maxPerUser, MaxPerIP: maxPerIP, Window: window, Now: time.Now}
}

// Check увеличивает счётчики и возвращает причины превышения.
// degraded=true означает «Redis недоступен, L2 пропущена» — ядро не должно блокировать трафик из-за этого.
func (l *Limiter) Check(ctx context.Context, t decision.Txn) (reasons []string, degraded bool) {
	over := func(prefix, id string, max int) (bool, error) {
		key := fmt.Sprintf("vel:%s:%s:%d", prefix, id, int(l.Window.Seconds()))
		now := l.Now()
		// member уникален для события: одна миллисекунда может нести несколько транзакций.
		member := fmt.Sprintf("%d-%06d", now.UnixNano(), rand.IntN(1e6))
		n, err := slidingCheck.Run(ctx, l.rdb, []string{key},
			now.UnixMilli(), l.Window.Milliseconds(), max, member).Int64()
		if err != nil {
			return false, err
		}
		return n > int64(max), nil
	}

	userOver, err := over("user", t.UserID, l.MaxPerUser)
	if err != nil {
		return nil, true
	}
	ipOver, err := over("ip", t.IP, l.MaxPerIP)
	if err != nil {
		return nil, true
	}

	if userOver {
		reasons = append(reasons, "velocity_user_limit")
	}
	if ipOver {
		reasons = append(reasons, "velocity_ip_limit")
	}
	return reasons, false
}

// MarkSeen отмечает transaction_id как обработанное (24ч).
// Возвращает true, если такая транзакция уже была — повтор не должен инкрементить velocity.
func (l *Limiter) MarkSeen(ctx context.Context, txnID string) (bool, error) {
	ok, err := l.rdb.SetNX(ctx, "seen:txn:"+txnID, 1, 24*time.Hour).Result()
	if err != nil {
		return false, err
	}
	return !ok, nil // ключ уже существовал → дубликат
}
