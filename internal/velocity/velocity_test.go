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
