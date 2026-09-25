package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/sanchyous/redflag-antifraud/internal/decider"
	"github.com/sanchyous/redflag-antifraud/internal/rules"
	"github.com/sanchyous/redflag-antifraud/internal/velocity"
)

func testServer(t *testing.T, maxPerUser int) http.Handler {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	scorer := &decider.Scorer{
		Rules: rules.Config{
			MaxAmount:         10000,
			AllowedCurrencies: []string{"RUB", "USD"},
			BlockedUsers:      []string{"bad-user"},
		},
		Vel: velocity.New(rdb, maxPerUser, 1000, time.Minute),
		Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
	srv := &Server{Decider: scorer, Store: nil, Log: scorer.Log}
	return srv.Routes()
}

func postDecision(t *testing.T, h http.Handler, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/decisions", bytes.NewBufferString(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDecisionDenyBlacklist(t *testing.T) {
	h := testServer(t, 100)
	rec := postDecision(t, h,
		`{"transaction_id":"t1","user_id":"bad-user","amount":100,"currency":"RUB","ip":"1.2.3.4"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var v struct {
		Decision  string   `json:"decision"`
		Reasons   []string `json:"reasons"`
		RequestID string   `json:"request_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", v.Decision)
	}
	if len(v.Reasons) == 0 || v.Reasons[0] != "user_blacklisted" {
		t.Fatalf("reasons = %v", v.Reasons)
	}
	if v.RequestID == "" {
		t.Fatal("request_id must be present in response")
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Fatal("X-Request-Id header must be set")
	}
}

func TestDecisionAllowCleanTxn(t *testing.T) {
	h := testServer(t, 100)
	rec := postDecision(t, h,
		`{"transaction_id":"t2","user_id":"u-1","amount":500,"currency":"RUB","ip":"1.2.3.4"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var v struct {
		Decision string `json:"decision"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", v.Decision)
	}
}

func TestDecisionReviewOnVelocityBurst(t *testing.T) {
	h := testServer(t, 2) // лимит 2 транзакции на пользователя
	// Серия транзакций с разными transaction_id: одинаковый id был бы подавлен
	// дедупом идемпотентности (ретрай той же транзакции не кормит velocity).
	body := func(id string) string {
		return `{"transaction_id":"` + id + `","user_id":"u-burst","amount":10,"currency":"RUB","ip":"9.9.9.9"}`
	}
	for _, id := range []string{"t1", "t2"} {
		if rec := postDecision(t, h, body(id), nil); rec.Code != http.StatusOK {
			t.Fatalf("iteration %s: status = %d", id, rec.Code)
		}
	}
	rec := postDecision(t, h, body("t3"), nil)
	var v struct {
		Decision string   `json:"decision"`
		Reasons  []string `json:"reasons"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Decision != "review" {
		t.Fatalf("decision = %q, want review (body=%s)", v.Decision, rec.Body.String())
	}
	if len(v.Reasons) == 0 || v.Reasons[0] != "velocity_user_limit" {
		t.Fatalf("reasons = %v", v.Reasons)
	}
}

func TestDecisionValidation400(t *testing.T) {
	h := testServer(t, 100)
	rec := postDecision(t, h, `{"user_id":"u-1","amount":10}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestDecisionInvalidJSON400(t *testing.T) {
	h := testServer(t, 100)
	rec := postDecision(t, h, `{broken`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestRequestIDFromClientRespected(t *testing.T) {
	h := testServer(t, 100)
	rec := postDecision(t, h,
		`{"transaction_id":"t4","user_id":"u-1","amount":1,"currency":"RUB","ip":"1.1.1.1"}`,
		map[string]string{"X-Request-Id": "my-trace-123"})
	if got := rec.Header().Get("X-Request-Id"); got != "my-trace-123" {
		t.Fatalf("X-Request-Id = %q, want client-provided", got)
	}
}

func TestRecentWithoutStore503(t *testing.T) {
	h := testServer(t, 100)
	req := httptest.NewRequest(http.MethodGet, "/v1/decisions/recent", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestHealth(t *testing.T) {
	h := testServer(t, 100)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}
