package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/engine"
	"github.com/sanchyous/redflag-antifraud/internal/journal"
	"github.com/sanchyous/redflag-antifraud/internal/numplan"
	"github.com/sanchyous/redflag-antifraud/internal/protect"
	"github.com/sanchyous/redflag-antifraud/internal/store"
)

func testPlan(t testing.TB) *numplan.Plan {
	var sb strings.Builder
	sb.WriteString("АВС/ DEF;От;До;Емкость;Оператор;Регион;Территория ГАР;ИНН\n")
	sb.WriteString("495;0000000;9999999;10000000;ПАО МГТС;г. Москва;Город Москва;7710016640\n")
	sb.WriteString("916;0000000;9999999;10000000;ПАО \"МТС\";г. Москва и Московская область;Город Москва, Московская область;7740000076\n")
	b := numplan.NewBuilder()
	if err := b.AddCSV(strings.NewReader(sb.String())); err != nil {
		t.Fatal(err)
	}
	p, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newServer(t testing.TB, mut func(*Server)) *Server {
	fixed := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	eng, err := engine.New(engine.Config{Plan: testPlan(t), Now: func() time.Time { return fixed }, MaxFutureSkew: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Engine: eng, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), FailOpen: true}
	if mut != nil {
		mut(s)
	}
	return s
}

func do(t testing.TB, h http.Handler, method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

const tzCall = `{"call_id":"tz-1","caller":"+7 495 ***-**-12","callee":"+7 916 ***-**-83",
"started_at":"2026-10-14T11:42:00+03:00","duration_sec":6,"src_country":"DE"}`

func decode[T any](t testing.TB, rr *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rr.Body.String(), err)
	}
	return v
}

func TestHealth(t *testing.T) {
	rr := do(t, newServer(t, nil).Routes(), "GET", "/health", "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"status":"ok"`) {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
}

func TestScoreTZScenario(t *testing.T) {
	h := newServer(t, nil).Routes()
	rr := do(t, h, "POST", "/v1/calls/score", tzCall)
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	resp := decode[engine.Response](t, rr)
	if resp.Decision != "review" || resp.Caller.Masked != "+7 495 ***-**-12" || resp.Callee.Masked != "+7 916 ***-**-83" {
		t.Fatalf("resp = %+v", resp)
	}
	var spoof bool
	for _, r := range resp.Reasons {
		if r.Factor == "spoof" && r.Text != "" && r.Contribution > 0 {
			spoof = true
		}
	}
	if !spoof {
		t.Fatalf("spoof reason missing: %+v", resp.Reasons)
	}
	if rr.Header().Get("X-Request-Id") == "" {
		t.Fatal("request id header")
	}
	if resp.Stage != "linear" {
		t.Fatalf("without ML the stage must be linear, got %q", resp.Stage)
	}
}

func TestScoreRawNumbersNeverEchoed(t *testing.T) {
	h := newServer(t, nil).Routes()
	rr := do(t, h, "POST", "/v1/calls/score",
		`{"call_id":"p-1","caller":"+7 916 123-45-67","callee":"+7 495 765-43-21","duration_sec":30}`)
	body := rr.Body.String()
	for _, raw := range []string{"1234567", "7654321", "123-45-67", "765-43-21"} {
		if strings.Contains(body, raw) {
			t.Fatalf("response leaks raw number fragment %q: %s", raw, body)
		}
	}
}

func TestScoreValidation(t *testing.T) {
	h := newServer(t, nil).Routes()
	cases := map[string]string{
		`{`: "invalid_json",
		`{"caller":"+7 916 123-45-67","callee":"+7 495 765-43-21"}`:        "call_id_required",
		`{"call_id":"a","caller":"+7 916 123-45-67"}`:                      "callee_required",
		`{"call_id":"b","callee":"не номер"}`:                              "callee_invalid",
		`{"call_id":"c","callee":"+7 495 765-43-21","duration_sec":-3}`:    "duration_negative",
		`{"call_id":"d","callee":"+7 495 765-43-21","conn_type":"pigeon"}`: "conn_type_invalid",
	}
	for body, want := range cases {
		rr := do(t, h, "POST", "/v1/calls/score", body)
		got := decode[map[string]string](t, rr)
		if rr.Code != 400 || got["error"] != want || got["request_id"] == "" {
			t.Fatalf("%s → %d %v, want 400 %s", body, rr.Code, got, want)
		}
	}
}

func TestFutureTimestampRejectedWhenStrict(t *testing.T) {
	h := newServer(t, nil).Routes()
	rr := do(t, h, "POST", "/v1/calls/score", `{"call_id":"f","callee":"+7 495 765-43-21","started_at":"2999-01-01T00:00:00Z"}`)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "started_at_in_future") {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
}

func TestScoreBodyTooLarge(t *testing.T) {
	h := newServer(t, nil).Routes()
	big := `{"call_id":"x","callee":"+7 495 765-43-21","src_operator":"` + strings.Repeat("A", 40<<10) + `"}`
	if rr := do(t, h, "POST", "/v1/calls/score", big); rr.Code != 400 {
		t.Fatalf("oversized body: %d", rr.Code)
	}
}

func TestEmergencyOverHTTP(t *testing.T) {
	h := newServer(t, nil).Routes()
	// экстренный вызов без call_id и с «мусорной» записью: не 400, а allow
	for _, body := range []string{
		`{"callee":"103","caller":"+7 495 123-45-67","src_country":"DE"}`,
		`{"call_id":"e1","callee":"*112#"}`,
		`{"call_id":"e2","caller":"103","callee":"+7 916 123-45-67"}`,
	} {
		rr := do(t, h, "POST", "/v1/calls/score", body)
		resp := decode[engine.Response](t, rr)
		if rr.Code != 200 || resp.Decision != "allow" || resp.SafeClass != "emergency" {
			t.Fatalf("%s → %d %+v", body, rr.Code, resp)
		}
	}
}

func TestAuth(t *testing.T) {
	h := newServer(t, func(s *Server) { s.APIKey = "secret" }).Routes()
	if rr := do(t, h, "POST", "/v1/calls/score", tzCall); rr.Code != 401 {
		t.Fatalf("no key: %d", rr.Code)
	}
	if rr := do(t, h, "POST", "/v1/calls/score", tzCall, "X-API-Key", "wrong"); rr.Code != 401 {
		t.Fatalf("wrong key: %d", rr.Code)
	}
	if rr := do(t, h, "POST", "/v1/calls/score", tzCall, "X-API-Key", "secret"); rr.Code != 200 {
		t.Fatalf("right key: %d", rr.Code)
	}
	if rr := do(t, h, "GET", "/health", ""); rr.Code != 200 {
		t.Fatal("/health must stay open")
	}
	if rr := do(t, h, "GET", "/metrics", ""); rr.Code != 200 {
		t.Fatal("/metrics must stay open")
	}
	if rr := do(t, h, "GET", "/v1/calls/recent", ""); rr.Code != 401 {
		t.Fatal("recent must be protected")
	}
}

func TestBatch(t *testing.T) {
	h := newServer(t, nil).Routes()
	body := `{"calls":[
	  {"call_id":"b1","caller":"+7 916 123-45-67","callee":"+7 495 765-43-21","duration_sec":90},
	  {"call_id":"b2","callee":"мусор"},
	  {"call_id":"b3","callee":"103"},
	  {"call_id":"b1","caller":"+7 916 123-45-67","callee":"+7 495 765-43-21","duration_sec":90}
	]}`
	rr := do(t, h, "POST", "/v1/calls/score/batch", body)
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	res := decode[struct{ Results []batchItem }](t, rr).Results
	if len(res) != 4 {
		t.Fatalf("results = %d", len(res))
	}
	if res[0].Result == nil || res[0].Result.Decision != "allow" || res[0].Error != "" {
		t.Fatalf("item 0: %+v", res[0])
	}
	if res[1].Error != "callee_invalid" || res[1].Result != nil {
		t.Fatalf("item 1: %+v", res[1])
	}
	if res[2].Result == nil || res[2].Result.SafeClass != "emergency" {
		t.Fatalf("item 2: %+v", res[2])
	}
	if res[3].Result == nil || !res[3].Result.Duplicate {
		t.Fatalf("item 3 must be a duplicate: %+v", res[3])
	}
}

func TestBatchLimits(t *testing.T) {
	h := newServer(t, nil).Routes()
	if rr := do(t, h, "POST", "/v1/calls/score/batch", `{"calls":[]}`); rr.Code != 400 || !strings.Contains(rr.Body.String(), "calls_required") {
		t.Fatalf("empty: %d %s", rr.Code, rr.Body)
	}
	var sb strings.Builder
	sb.WriteString(`{"calls":[`)
	for i := 0; i < maxBatchCalls+1; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"call_id":"x%d","callee":"+7 495 765-43-21"}`, i)
	}
	sb.WriteString(`]}`)
	if rr := do(t, h, "POST", "/v1/calls/score/batch", sb.String()); rr.Code != 400 || !strings.Contains(rr.Body.String(), "batch_too_large") {
		t.Fatalf("too large: %d %s", rr.Code, rr.Body)
	}
	if rr := do(t, h, "POST", "/v1/calls/score/batch", `{`); rr.Code != 400 {
		t.Fatalf("bad json: %d", rr.Code)
	}
}

func TestMetrics(t *testing.T) {
	s := newServer(t, nil)
	h := s.Routes()
	do(t, h, "POST", "/v1/calls/score", tzCall)
	do(t, h, "POST", "/v1/calls/score", `{"call_id":"m2","callee":"103"}`)
	rr := do(t, h, "GET", "/metrics", "")
	body := rr.Body.String()
	for _, want := range []string{
		`redflag_decisions_total{decision="review"} 1`,
		`redflag_decisions_total{decision="allow"} 1`,
		`redflag_emergency_total 1`,
		`redflag_score_latency_seconds_count 2`,
		`redflag_score_latency_seconds_bucket{le="+Inf"} 2`,
		`redflag_tracked_numbers`,
		`redflag_ml_calls_total 0`,
		`redflag_ml_skipped_total 0`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics lack %q:\n%s", want, body)
		}
	}
	if !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain") {
		t.Fatal("metrics content type")
	}
}

func TestLatencyHistBuckets(t *testing.T) {
	var h latencyHist
	h.observe(10 * time.Microsecond)
	h.observe(30 * time.Microsecond)
	h.observe(time.Second)
	if h.buckets[0].Load() != 1 || h.buckets[1].Load() != 1 || h.buckets[len(latBounds)].Load() != 1 || h.count.Load() != 3 {
		t.Fatalf("buckets: %d %d ... last %d, count %d", h.buckets[0].Load(), h.buckets[1].Load(), h.buckets[len(latBounds)].Load(), h.count.Load())
	}
}

type memSink struct {
	mu   sync.Mutex
	recs []store.Record
}

func (m *memSink) SaveBatch(_ context.Context, recs []store.Record) error {
	m.mu.Lock()
	m.recs = append(m.recs, recs...)
	m.mu.Unlock()
	return nil
}

func TestJournalReceivesFlaggedOnly(t *testing.T) {
	sink := &memSink{}
	j := journal.New(sink, journal.Config{FlushEvery: 5 * time.Millisecond}, nil)
	s := newServer(t, func(s *Server) { s.Journal = j })
	h := s.Routes()
	do(t, h, "POST", "/v1/calls/score", tzCall) // review
	do(t, h, "POST", "/v1/calls/score",
		`{"call_id":"ok","caller":"+7 916 123-45-67","callee":"+7 495 765-43-21","duration_sec":100}`) // allow
	j.Close()
	if len(sink.recs) != 1 || sink.recs[0].CallID != "tz-1" || sink.recs[0].Decision != "review" {
		t.Fatalf("journal = %+v", sink.recs)
	}
	r := sink.recs[0]
	if r.CallerMasked != "+7 495 ***-**-12" || len(r.Reasons) < 3 || r.ModelVersion == "" {
		t.Fatalf("record content: %+v", r)
	}
	if strings.Contains(r.CallerMasked+r.CalleeMasked, "1234") {
		t.Fatal("no raw numbers in journal")
	}
}

func TestRecentWithoutStore(t *testing.T) {
	h := newServer(t, nil).Routes()
	if rr := do(t, h, "GET", "/v1/calls/recent", ""); rr.Code != 503 {
		t.Fatalf("code %d", rr.Code)
	}
}

func TestRecentParamValidation(t *testing.T) {
	// Store != nil нужен для дошедшей проверки параметров; проверяем ответы 400 до обращения к БД.
	h := newServer(t, func(s *Server) { s.Store = &store.Store{} }).Routes()
	for _, q := range []string{"limit=0", "limit=201", "limit=abc"} {
		if rr := do(t, h, "GET", "/v1/calls/recent?"+q, ""); rr.Code != 400 || !strings.Contains(rr.Body.String(), "invalid_limit") {
			t.Fatalf("%s: %d %s", q, rr.Code, rr.Body)
		}
	}
	if rr := do(t, h, "GET", "/v1/calls/recent?decision=maybe", ""); rr.Code != 400 || !strings.Contains(rr.Body.String(), "invalid_decision") {
		t.Fatalf("decision: %d %s", rr.Code, rr.Body)
	}
}

func TestFallbackModes(t *testing.T) {
	c1 := callFor("+7 916 123-45-67", "+7 495 765-43-21")
	if r := fallback(c1, true); r.Decision != "allow" || r.Reasons[0].Factor != "internal_error" {
		t.Fatalf("open: %+v", r)
	}
	if r := fallback(c1, false); r.Decision != "review" {
		t.Fatalf("closed: %+v", r)
	}
	em := callFor("+7 916 123-45-67", "*103#")
	for _, open := range []bool{true, false} {
		if r := fallback(em, open); r.Decision != "allow" || r.SafeClass != protect.Emergency.String() {
			t.Fatalf("emergency must be allow in both modes (open=%v): %+v", open, r)
		}
	}
}

func TestPanicRecovery(t *testing.T) {
	s := newServer(t, nil)
	s.Engine = nil // любое обращение к движку паникует
	h := s.Routes()
	rr := do(t, h, "POST", "/v1/calls/score", `{"call_id":"p","caller":"+7 916 123-45-67","callee":"+7 495 765-43-21"}`)
	// /health тоже трогает движок → отдельный вызов ниже; здесь важна судьба скоринга
	if rr.Code != 200 {
		t.Fatalf("panic must be handled by FAIL_MODE, got %d %s", rr.Code, rr.Body)
	}
	resp := decode[engine.Response](t, rr)
	if resp.Decision != "allow" || resp.Reasons[0].Factor != "internal_error" {
		t.Fatalf("open mode fallback: %+v", resp)
	}
	s.FailOpen = false
	resp = decode[engine.Response](t, do(t, s.Routes(), "POST", "/v1/calls/score",
		`{"call_id":"p2","caller":"+7 916 123-45-67","callee":"+7 495 765-43-21"}`))
	if resp.Decision != "review" {
		t.Fatalf("closed mode fallback: %+v", resp)
	}
	resp = decode[engine.Response](t, do(t, s.Routes(), "POST", "/v1/calls/score", `{"callee":"103"}`))
	if resp.Decision != "allow" || resp.SafeClass != "emergency" {
		t.Fatalf("emergency during outage: %+v", resp)
	}
}

func TestDocsAndSpec(t *testing.T) {
	h := newServer(t, nil).Routes()
	if rr := do(t, h, "GET", "/docs", ""); rr.Code != 200 || !strings.Contains(rr.Body.String(), "swagger") {
		t.Fatalf("docs: %d", rr.Code)
	}
	rr := do(t, h, "GET", "/openapi.yaml", "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "/v1/calls/score") {
		t.Fatalf("spec: %d", rr.Code)
	}
}

func TestRequestIDPropagation(t *testing.T) {
	h := newServer(t, nil).Routes()
	rr := do(t, h, "POST", "/v1/calls/score", `{`, "X-Request-Id", "abc-123")
	if rr.Header().Get("X-Request-Id") != "abc-123" || !strings.Contains(rr.Body.String(), "abc-123") {
		t.Fatalf("request id not propagated: %s", rr.Body)
	}
}

func TestConcurrentRequests(t *testing.T) {
	h := newServer(t, nil).Routes()
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				body := fmt.Sprintf(`{"call_id":"g%d-%d","caller":"+7 916 %03d-00-%02d","callee":"+7 495 700-00-%02d","duration_sec":%d}`, g, i, g, i%100, i%100, i%120)
				rr := do(t, h, "POST", "/v1/calls/score", body)
				if rr.Code != 200 {
					errs <- fmt.Sprintf("%d %s", rr.Code, rr.Body)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

func BenchmarkScoreHTTP(b *testing.B) {
	h := newServer(b, nil).Routes()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			body := fmt.Sprintf(`{"call_id":"b-%p-%d","caller":"+7 916 %03d-00-%02d","callee":"+7 495 700-00-%02d","duration_sec":%d}`, &pb, i, i%1000, i%100, i%100, i%120)
			req := httptest.NewRequest("POST", "/v1/calls/score", bytes.NewBufferString(body))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
		}
	})
}
