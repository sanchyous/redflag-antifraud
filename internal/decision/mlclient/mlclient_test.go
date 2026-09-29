package mlclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/detection/features"
)

func vec() *features.Vector {
	var v features.Vector
	v.Raw[features.OutCalls1h] = 340
	v.Raw[features.Spoof] = 1
	return &v
}

func TestScoreRoundTrip(t *testing.T) {
	var got scoreRequest
	var key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("X-API-Key")
		if r.URL.Path != "/v1/score" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(Result{Score: 0.93, Logit: 2.6, ModelVersion: "m1",
			Contributions: []Contribution{{Feature: "spoof", Value: 1, Contribution: 3.1}}})
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL + "/", APIKey: "k", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Score(context.Background(), vec(), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Score != 0.93 || res.ModelVersion != "m1" || len(res.Contributions) != 1 || res.Contributions[0].Feature != "spoof" {
		t.Fatalf("result = %+v", res)
	}
	if key != "k" || !got.Explain || len(got.Features) != features.N || got.Features["out_calls_1h"] != 340 || got.Features["spoof"] != 1 {
		t.Fatalf("request = %+v key=%q", got, key)
	}
	for _, n := range features.Names {
		if _, ok := got.Features[n]; !ok {
			t.Fatalf("feature %s missing in request", n)
		}
	}
}

func TestInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Info{Version: "v", Thresholds: map[string]float64{"review": 0.2, "block": 0.9, "gate": 0.05}})
	}))
	defer srv.Close()
	c, _ := New(Config{BaseURL: srv.URL})
	inf, err := c.Info(context.Background())
	if err != nil || inf.Version != "v" || inf.Thresholds["block"] != 0.9 {
		t.Fatalf("%+v %v", inf, err)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{BaseURL: "  "}); err == nil {
		t.Fatal("empty URL must be rejected")
	}
}

func TestErrorStatuses(t *testing.T) {
	var status atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(`{"detail":"boom"}`))
	}))
	defer srv.Close()
	c, _ := New(Config{BaseURL: srv.URL, BreakerFailures: 1000})
	status.Store(503)
	if _, err := c.Score(context.Background(), vec(), false); !errors.Is(err, ErrNoModel) {
		t.Fatalf("503 → %v", err)
	}
	status.Store(422)
	if _, err := c.Score(context.Background(), vec(), false); err == nil {
		t.Fatal("422 must be an error")
	}
	status.Store(200) // 200 с телом, не похожим на оценку (нет model_version)
	if _, err := c.Score(context.Background(), vec(), false); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("garbage 200 must be rejected: %v", err)
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(Result{Score: 0.5, ModelVersion: "m"})
	}))
	defer srv.Close()
	c, _ := New(Config{BaseURL: srv.URL, Timeout: 20 * time.Millisecond})
	start := time.Now()
	if _, err := c.Score(context.Background(), vec(), false); err == nil {
		t.Fatal("slow ML must time out")
	}
	if time.Since(start) > 150*time.Millisecond {
		t.Fatalf("timeout not enforced: %s", time.Since(start))
	}
}

func TestBreakerOpensAndRecovers(t *testing.T) {
	var healthy atomic.Bool
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !healthy.Load() {
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(Result{Score: 0.7, ModelVersion: "m"})
	}))
	defer srv.Close()
	now := time.Unix(1000, 0)
	var nowMu sync.Mutex
	clock := func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now }
	advance := func(d time.Duration) { nowMu.Lock(); now = now.Add(d); nowMu.Unlock() }
	c, _ := New(Config{BaseURL: srv.URL, BreakerFailures: 3, BreakerCooldown: 10 * time.Second, Now: clock})

	for i := 0; i < 3; i++ {
		if _, err := c.Score(context.Background(), vec(), false); err == nil || errors.Is(err, ErrBreakerOpen) {
			t.Fatalf("failure %d: %v", i, err)
		}
	}
	if !c.Open() {
		t.Fatal("breaker must be open after 3 failures")
	}
	before := calls.Load()
	if _, err := c.Score(context.Background(), vec(), false); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("open breaker must reject: %v", err)
	}
	if calls.Load() != before {
		t.Fatal("open breaker must not hit the network")
	}
	advance(11 * time.Second) // cooldown прошёл, ML ожил → проба проходит и закрывает breaker
	healthy.Store(true)
	if res, err := c.Score(context.Background(), vec(), false); err != nil || res.Score != 0.7 {
		t.Fatalf("probe: %+v %v", res, err)
	}
	if c.Open() {
		t.Fatal("successful probe must close the breaker")
	}
}

func TestBreakerAllowsSingleProbe(t *testing.T) {
	c, _ := New(Config{BaseURL: "http://127.0.0.1:1", BreakerFailures: 1, BreakerCooldown: time.Second,
		Now: func() time.Time { return time.Unix(5000, 0) }})
	c.record(errors.New("x")) // открыть
	c.mu.Lock()
	c.openedAt = time.Unix(1, 0) // давно
	c.mu.Unlock()
	first, second := c.allow(), c.allow()
	if !first || second {
		t.Fatalf("exactly one probe must pass: %v %v", first, second)
	}
	c.record(errors.New("still down")) // проба провалилась → снова закрыто для всех до cooldown
	if c.allow() {
		t.Fatal("failed probe must reopen the breaker")
	}
}

func TestConcurrentUse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Result{Score: 0.4, ModelVersion: "m"})
	}))
	defer srv.Close()
	c, _ := New(Config{BaseURL: srv.URL, Timeout: time.Second})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := c.Score(context.Background(), vec(), false); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestWarmupUsesLongTimeoutAndBypassesBreaker(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(120 * time.Millisecond) // «холодный» первый запрос дольше боевого таймаута
		_ = json.NewEncoder(w).Encode(Result{Score: 0.1, ModelVersion: "m"})
	}))
	defer srv.Close()
	c, _ := New(Config{BaseURL: srv.URL, Timeout: 30 * time.Millisecond, BreakerFailures: 1})
	if _, err := c.Score(context.Background(), vec(), false); err == nil {
		t.Fatal("premise: the regular timeout is shorter than the cold request")
	}
	if !c.Open() {
		t.Fatal("premise: the breaker must be open now")
	}
	if err := c.Warmup(context.Background()); err != nil {
		t.Fatalf("warmup must succeed with its long timeout even with an open breaker: %v", err)
	}
	if c.cfg.Timeout != 30*time.Millisecond {
		t.Fatalf("regular timeout must stay untouched, got %v", c.cfg.Timeout)
	}
	if calls.Load() != 2 {
		t.Fatalf("server calls = %d", calls.Load())
	}
}

func TestScoreOutOfRangeRejected(t *testing.T) {
	for _, body := range []string{`{"score":1.7,"model_version":"m"}`, `{"score":-0.1,"model_version":"m"}`} {
		body := body
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		c, _ := New(Config{BaseURL: srv.URL})
		if _, err := c.Score(context.Background(), vec(), false); !errors.Is(err, ErrBadResponse) {
			t.Fatalf("%s → %v", body, err)
		}
		srv.Close()
	}
}
