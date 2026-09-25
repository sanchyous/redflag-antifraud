package decider_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/sanchyous/redflag-antifraud/internal/decider"
	"github.com/sanchyous/redflag-antifraud/internal/decision"
	"github.com/sanchyous/redflag-antifraud/internal/rules"
	"github.com/sanchyous/redflag-antifraud/internal/velocity"
)

func txn(id, userID, ip string) decision.Txn {
	return decision.Txn{TransactionID: id, UserID: userID, IP: ip, Amount: 100, Currency: "RUB"}
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func velLimiter(t *testing.T, maxUser, maxIP int) (*velocity.Limiter, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return velocity.New(rdb, maxUser, maxIP, time.Minute), rdb
}

// scorerWith собирает Scorer; extHandler != nil — подключает HTTP-заглушку внешнего scorer.
func scorerWith(t *testing.T, opts func(s *decider.Scorer), extHandler http.HandlerFunc) *decider.Scorer {
	t.Helper()
	s := &decider.Scorer{Log: silentLogger()}
	if extHandler != nil {
		srv := httptest.NewServer(extHandler)
		t.Cleanup(srv.Close)
		s.ScorerURL = srv.URL
		s.HTTP = srv.Client()
	}
	if opts != nil {
		opts(s)
	}
	return s
}

func allow(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{"score": 0.1, "decision": "allow"})
}

// L1 deny должен отсекать pipeline до вызова внешнего scorer.
func TestL1ShortCircuitsExternalScorer(t *testing.T) {
	calls := 0
	s := scorerWith(t, func(s *decider.Scorer) {
		s.Rules = rules.Config{BlockedUsers: []string{"bad"}}
	}, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"decision": "deny"})
	})

	v := s.Evaluate(context.Background(), txn("t1", "bad", "1.2.3.4"), "req-1")
	if v.Decision != decision.Deny {
		t.Fatalf("want deny, got %s (%v)", v.Decision, v.Reasons)
	}
	if calls != 0 {
		t.Fatalf("external scorer must not be called on L1 deny, got %d calls", calls)
	}
}

// Регресс главного кейса ревью: честный allow от scorer не превращает allow в review.
func TestExternalAllowKeepsAllow(t *testing.T) {
	s := scorerWith(t, nil, allow)
	v := s.Evaluate(context.Background(), txn("t1", "u1", "1.2.3.4"), "req-1")
	if v.Decision != decision.Allow {
		t.Fatalf("honest allow must stay allow, got %s (%v)", v.Decision, v.Reasons)
	}
}

// L2 review + внешний allow: вердикт не может быть ослаблен.
func TestExternalAllowDoesNotDowngradeReview(t *testing.T) {
	vel, _ := velLimiter(t, 0, 100) // max=0: любое событие = превышение
	s := scorerWith(t, func(s *decider.Scorer) { s.Vel = vel }, allow)

	v := s.Evaluate(context.Background(), txn("t1", "u1", "1.2.3.4"), "req-1")
	if v.Decision != decision.Review {
		t.Fatalf("L2 review must survive external allow, got %s (%v)", v.Decision, v.Reasons)
	}
	if !strings.Contains(strings.Join(v.Reasons, ","), "velocity_user_limit") {
		t.Fatalf("review must carry L2 reason, got %v", v.Reasons)
	}
}

func TestExternalDenyEscalates(t *testing.T) {
	s := scorerWith(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"score": 0.9, "decision": "deny"})
	})
	v := s.Evaluate(context.Background(), txn("t1", "u1", "1.2.3.4"), "req-1")
	if v.Decision != decision.Deny {
		t.Fatalf("external deny must escalate to deny, got %s", v.Decision)
	}
}

// Внешний сервис может вернуть decision в любом регистре — не молча игнорируем.
func TestExternalDecisionNormalized(t *testing.T) {
	s := scorerWith(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"score": 0.9, "decision": "DENY"})
	})
	v := s.Evaluate(context.Background(), txn("t1", "u1", "1.2.3.4"), "req-1")
	if v.Decision != decision.Deny {
		t.Fatalf("DENY must normalize to deny, got %s", v.Decision)
	}
}

func TestExternalScoreTriggersReview(t *testing.T) {
	s := scorerWith(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"score": 0.9})
	})
	v := s.Evaluate(context.Background(), txn("t1", "u1", "1.2.3.4"), "req-1")
	if v.Decision != decision.Review {
		t.Fatalf("score 0.9 must escalate to review, got %s", v.Decision)
	}
	if !strings.Contains(strings.Join(v.Reasons, ","), "external_scorer_hit") {
		t.Fatalf("want external_scorer_hit reason, got %v", v.Reasons)
	}
}

// FAIL_MODE: closed эскалирует ошибку scorer до review, open (по умолчанию) — пропускает.
func TestFailClosedExternalScorerError(t *testing.T) {
	fail := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }

	closed := scorerWith(t, func(s *decider.Scorer) { s.FailOpen = false }, fail)
	v := closed.Evaluate(context.Background(), txn("t1", "u1", "1.2.3.4"), "req-1")
	if v.Decision != decision.Review {
		t.Fatalf("fail-closed: want review, got %s (%v)", v.Decision, v.Reasons)
	}

	open := scorerWith(t, func(s *decider.Scorer) { s.FailOpen = true }, fail)
	v = open.Evaluate(context.Background(), txn("t1", "u1", "1.2.3.4"), "req-1")
	if v.Decision != decision.Allow {
		t.Fatalf("fail-open: want allow, got %s (%v)", v.Decision, v.Reasons)
	}
}

// FAIL_MODE=closed на недоступном Redis.
func TestFailClosedRedisDown(t *testing.T) {
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond, ReadTimeout: 100 * time.Millisecond})
	t.Cleanup(func() { _ = dead.Close() })

	mk := func(failOpen bool) *decider.Scorer {
		return scorerWith(t, func(s *decider.Scorer) {
			s.Vel = velocity.New(dead, 10, 10, time.Minute)
			s.FailOpen = failOpen
		}, allow)
	}

	v := mk(false).Evaluate(context.Background(), txn("t1", "u1", "1.2.3.4"), "req-1")
	if v.Decision != decision.Review {
		t.Fatalf("fail-closed: want review, got %s (%v)", v.Decision, v.Reasons)
	}
	if !strings.Contains(strings.Join(v.Reasons, ","), "velocity_degraded") {
		t.Fatalf("want velocity_degraded reason, got %v", v.Reasons)
	}

	v = mk(true).Evaluate(context.Background(), txn("t1", "u1", "1.2.3.4"), "req-1")
	if v.Decision != decision.Allow {
		t.Fatalf("fail-open: want allow, got %s (%v)", v.Decision, v.Reasons)
	}
}

// Дубликат transaction_id не должен второй раз инкрементить velocity.
func TestDuplicateTransactionDoesNotDoubleCount(t *testing.T) {
	vel, rdb := velLimiter(t, 100, 100)
	s := scorerWith(t, func(s *decider.Scorer) { s.Vel = vel }, nil)
	ctx := context.Background()

	_ = s.Evaluate(ctx, txn("dup-1", "u1", "1.1.1.1"), "r1")
	v2 := s.Evaluate(ctx, txn("dup-1", "u1", "1.1.1.1"), "r2")

	if !strings.Contains(strings.Join(v2.Reasons, ","), "duplicate_transaction") {
		t.Fatalf("duplicate must be flagged, got %v", v2.Reasons)
	}
	n, err := rdb.ZCard(ctx, "vel:user:u1:60").Result()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("velocity must count exactly 1 event for duplicate, got %d", n)
	}
}

// reasons в JSON — всегда массив, не null.
func TestReasonsNeverNull(t *testing.T) {
	s := scorerWith(t, nil, nil)
	v := s.Evaluate(context.Background(), txn("t1", "u1", "1.2.3.4"), "req-1")
	if v.Reasons == nil {
		t.Fatal("reasons must be [] not nil")
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"reasons":null`) {
		t.Fatalf("reasons serialized as null: %s", b)
	}
}
