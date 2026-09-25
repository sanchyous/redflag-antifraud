// Package velocity — L2: учёт частоты действий в скользящих окнах Redis.
package velocity

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sanchyous/redflag-antifraud/internal/decision"
)

// Limiter считает транзакции пользователя и IP в окне Window.
type Limiter struct {
	rdb        *redis.Client
	MaxPerUser int
	MaxPerIP   int
	Window     time.Duration
}

func New(rdb *redis.Client, maxPerUser, maxPerIP int, window time.Duration) *Limiter {
	return &Limiter{rdb: rdb, MaxPerUser: maxPerUser, MaxPerIP: maxPerIP, Window: window}
}

// Check увеличивает счётчики и возвращает причины превышения.
// degraded=true означает «Redis недоступен, L2 пропущена» — ядро не должно блокировать трафик из-за этого.
func (l *Limiter) Check(ctx context.Context, t decision.Txn) (reasons []string, degraded bool) {
	windowSec := int(l.Window.Seconds())
	check := func(prefix, id string, max int) (bool, error) {
		key := fmt.Sprintf("vel:%s:%s:%d", prefix, id, windowSec)
		n, err := l.rdb.Incr(ctx, key).Result()
		if err != nil {
			return false, err
		}
		if n == 1 {
			// первый инкремент в текущем окне — задаём жизнь окна
			l.rdb.Expire(ctx, key, l.Window)
		}
		return n > int64(max), nil
	}

	userOver, err := check("user", t.UserID, l.MaxPerUser)
	if err != nil {
		return nil, true
	}
	ipOver, err := check("ip", t.IP, l.MaxPerIP)
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
