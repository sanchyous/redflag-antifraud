package velocity

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/sanchyous/redflag-antifraud/internal/decision"
)

func txn(userID, ip string) decision.Txn {
	return decision.Txn{TransactionID: "t", UserID: userID, IP: ip, Amount: 1, Currency: "RUB"}
}

func TestVelocityTriggersOnBurst(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	l := New(rdb, 3, 100, time.Minute)
	ctx := context.Background()

	var gotReview bool
	for i := 1; i <= 5; i++ {
		reasons, degraded := l.Check(ctx, txn("u-1", "10.0.0.1"))
		if degraded {
			t.Fatalf("iteration %d: unexpected degraded", i)
		}
		if i <= 3 && len(reasons) != 0 {
			t.Fatalf("iteration %d: early trigger %v", i, reasons)
		}
		if i == 4 {
			gotReview = len(reasons) == 1 && reasons[0] == "velocity_user_limit"
		}
	}
	if !gotReview {
		t.Fatal("user limit not triggered on 4th txn")
	}
}

func TestVelocityIPAndUserIndependent(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	l := New(rdb, 100, 2, time.Minute)
	ctx := context.Background()

	// один IP, разные пользователи: на 3-й транзакции с этого IP должен сработать IP-лимит
	_, _ = l.Check(ctx, txn("u-1", "10.0.0.9"))
	_, _ = l.Check(ctx, txn("u-2", "10.0.0.9"))
	reasons, degraded := l.Check(ctx, txn("u-3", "10.0.0.9"))
	if degraded {
		t.Fatal("unexpected degraded")
	}
	if len(reasons) != 1 || reasons[0] != "velocity_ip_limit" {
		t.Fatalf("want ip limit, got %v", reasons)
	}
}

func TestVelocityDegradedWhenRedisDown(t *testing.T) {
	// порт, где гарантированно никто не слушает
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond, ReadTimeout: 100 * time.Millisecond})
	l := New(rdb, 1, 1, time.Minute)
	_, degraded := l.Check(context.Background(), txn("u-1", "10.0.0.1"))
	if !degraded {
		t.Fatal("want degraded=true when redis unreachable")
	}
}

// Честное скользящее окно: события на границе остаются в счёте.
// Fixed window на t=61с начал бы новый чистый счётчик — этот тест такое ловит.
func TestVelocitySlidingWindowCatchesBoundary(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	l := New(rdb, 2, 1000, time.Minute)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var offset time.Duration
	l.Now = func() time.Time { return base.Add(offset) }
	step := func(sec int) bool {
		offset = time.Duration(sec) * time.Second
		reasons, degraded := l.Check(context.Background(), txn("u-slide", "10.9.0.1"))
		if degraded {
			t.Fatalf("at %ds: unexpected degraded", sec)
		}
		return len(reasons) > 0
	}
	_ = step(0)  // n=1
	_ = step(55) // n=2 — в пределах max
	if !step(59) {
		t.Fatal("3rd txn in window must trigger (n=3 > max=2)")
	}
	// Событие t=0с уже вышло из окна, но 55с+59с+61с = 3 > max.
	if !step(61) {
		t.Fatal("sliding window must keep counting 55s+59s at t=61s")
	}
}

// EXPIRE не теряется: после Check ключ обязан иметь TTL (иначе счётчик живёт вечно).
func TestVelocityKeyHasTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	l := New(rdb, 10, 10, time.Minute)
	if _, degraded := l.Check(context.Background(), txn("u-ttl", "10.9.0.2")); degraded {
		t.Fatal("unexpected degraded")
	}
	ttl := rdb.TTL(context.Background(), "vel:user:u-ttl:60").Val()
	if ttl <= 0 || ttl > time.Minute {
		t.Fatalf("key must have TTL within window, got %v", ttl)
	}
}

func TestMarkSeenDetectsDuplicate(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	l := New(rdb, 10, 10, time.Minute)
	ctx := context.Background()
	seen, err := l.MarkSeen(ctx, "tx-1")
	if err != nil || seen {
		t.Fatalf("first sight: seen=%v err=%v", seen, err)
	}
	seen, err = l.MarkSeen(ctx, "tx-1")
	if err != nil || !seen {
		t.Fatalf("second sight must be duplicate: seen=%v err=%v", seen, err)
	}
}
