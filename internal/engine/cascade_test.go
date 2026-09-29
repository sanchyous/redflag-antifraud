package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/callrec"
	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/mlclient"
	"github.com/sanchyous/redflag-antifraud/internal/protect"
)

// fakeML — управляемый ML-сервис для тестов каскада.
type fakeML struct {
	srv      *httptest.Server
	score    atomic.Value // float64
	calls    atomic.Int32
	status   atomic.Int32
	contribs atomic.Value // []mlclient.Contribution
	info     atomic.Value // mlclient.Info
}

func newFakeML(t *testing.T) *fakeML {
	f := &fakeML{}
	f.score.Store(0.95)
	f.status.Store(200)
	f.contribs.Store([]mlclient.Contribution{
		{Feature: "spoof", Value: 1, Contribution: 2.9},
		{Feature: "foreign_ingress", Value: 1, Contribution: 0.8},
		{Feature: "call_duration", Value: 300, Contribution: -0.6},
	})
	f.info.Store(mlclient.Info{
		Version: "cb-test", Features: append([]string(nil), features.Names[:]...),
		Thresholds: map[string]float64{"review": 0.3, "block": 0.9, "gate": 0.02, "min_signals": 2},
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/model", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(f.info.Load().(mlclient.Info))
	})
	mux.HandleFunc("POST /v1/score", func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if st := int(f.status.Load()); st != 200 {
			w.WriteHeader(st)
			return
		}
		_ = json.NewEncoder(w).Encode(mlclient.Result{Score: f.score.Load().(float64), ModelVersion: "cb-test",
			Contributions: f.contribs.Load().([]mlclient.Contribution)})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func newCascade(t *testing.T, f *fakeML, mut func(*Config)) (*Engine, *clock) {
	cl, err := mlclient.New(mlclient.Config{BaseURL: f.srv.URL, Timeout: time.Second, BreakerFailures: 3, BreakerCooldown: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	e, clk := newEngine(t, func(c *Config) {
		c.ML = cl
		if mut != nil {
			mut(c)
		}
	})
	if err := e.RefreshML(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e, clk
}

func spoofCall(id string) *callrec.Call {
	c := call(id, "+7 495 123-45-67", "+7 916 123-45-67", t0, 6)
	c.SrcCountry = "DE"
	return c
}

func ordinaryCall(id string) *callrec.Call {
	return call(id, "+7 916 123-45-67", "+7 495 765-43-21", t0, 240)
}

func TestCascadeUsesMLForGrayZone(t *testing.T) {
	f := newFakeML(t)
	e, _ := newCascade(t, f, nil)
	r, err := e.Score(spoofCall("c-1"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Stage != "ml" || r.ModelVersion != "cb-test" || r.Score != 0.95 {
		t.Fatalf("stage/model/score: %+v", r)
	}
	if r.Decision != "review" { // один сильный сигнал (spoof) → block требует двух
		t.Fatalf("decision = %s", r.Decision)
	}
	if len(r.Reasons) != 3 || r.Reasons[0].Factor != "spoof" || r.Reasons[0].Text == "" || r.Reasons[2].Effect != "lowers" {
		t.Fatalf("reasons must come from ML SHAP: %+v", r.Reasons)
	}
	if e.Metrics.MLCalls.Load() != 1 || e.Metrics.MLDecisions.Load() != 1 || f.calls.Load() != 1 {
		t.Fatalf("metrics: calls=%d decisions=%d server=%d", e.Metrics.MLCalls.Load(), e.Metrics.MLDecisions.Load(), f.calls.Load())
	}
	if e.MLVersion() != "cb-test" {
		t.Fatal("MLVersion")
	}
}

func TestCascadeSkipsMLBelowGateWithoutSignals(t *testing.T) {
	f := newFakeML(t)
	e, _ := newCascade(t, f, nil)
	r, _ := e.Score(ordinaryCall("o-1"))
	if r.Stage != "linear" || r.Decision != "allow" {
		t.Fatalf("ordinary call must stay on stage 1: %+v", r)
	}
	if f.calls.Load() != 0 {
		t.Fatal("ML must not be called for ordinary traffic")
	}
}

func TestMLCanLowerFalsePositive(t *testing.T) {
	f := newFakeML(t)
	f.score.Store(0.01)
	e, _ := newCascade(t, f, nil)
	r, _ := e.Score(spoofCall("fp-1"))
	if r.Stage != "ml" || r.Decision != "allow" {
		t.Fatalf("ML says benign → allow: %+v", r)
	}
	if len(r.Reasons) != 0 {
		t.Fatalf("allow carries no reasons by default: %+v", r.Reasons)
	}
}

func TestMLBlockNeedsSignalsAndRespectsProtection(t *testing.T) {
	f := newFakeML(t)
	f.score.Store(0.99)
	cl := protect.New()
	cl.Add("+7 495 700-00-01")
	e, clk := newCascade(t, f, func(c *Config) { c.Classifier = cl })

	// массовый обзвон: несколько сильных сигналов + ML уверен → block
	last := sweep(e, clk, "+7 495 700-00-02", 90)
	if last.Decision != "block" || last.Stage != "ml" {
		t.Fatalf("expected ml block: %+v", last)
	}
	// то же с номера из allowlist → review, block подавлен
	prot := sweep(e, clk, "+7 495 700-00-01", 90)
	if prot.Decision != "review" || !prot.BlockSuppressed || prot.SafeClass != "allowlisted" {
		t.Fatalf("protected caller must never be blocked: %+v", prot)
	}
}

func TestEmergencyNeverReachesML(t *testing.T) {
	f := newFakeML(t)
	f.score.Store(0.999)
	e, _ := newCascade(t, f, nil)
	for _, callee := range []string{"103", "112", "*112#"} {
		r, err := e.Score(call("e-"+callee, "+7 495 123-45-67", callee, t0, 2))
		if err != nil || r.Decision != "allow" || r.SafeClass != "emergency" || r.Stage != "linear" {
			t.Fatalf("%s: %+v %v", callee, r, err)
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("emergency calls must never be sent to ML")
	}
}

func TestMLFailureFallsBackToStage1(t *testing.T) {
	f := newFakeML(t)
	f.status.Store(500)
	e, _ := newCascade(t, f, nil)
	r, err := e.Score(spoofCall("fb-1"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Stage != "linear" || r.Decision != "review" || r.ModelVersion != e.Model().Version {
		t.Fatalf("stage-1 verdict must survive an ML outage: %+v", r)
	}
	if e.Metrics.MLErrors.Load() != 1 {
		t.Fatalf("MLErrors = %d", e.Metrics.MLErrors.Load())
	}
	if len(r.Reasons) == 0 || r.Reasons[0].Factor != "spoof" {
		t.Fatalf("stage-1 explanation expected: %+v", r.Reasons)
	}
}

func TestBreakerStopsHammeringDeadML(t *testing.T) {
	f := newFakeML(t)
	f.status.Store(500)
	e, _ := newCascade(t, f, nil) // breaker: 3 сбоя
	for i := 0; i < 10; i++ {
		if _, err := e.Score(spoofCall(string(rune('a' + i)))); err != nil {
			t.Fatal(err)
		}
	}
	if f.calls.Load() != 3 {
		t.Fatalf("after 3 failures the breaker must stop requests: server saw %d", f.calls.Load())
	}
	if e.Metrics.MLSkipped.Load() != 7 || e.Metrics.MLErrors.Load() != 3 {
		t.Fatalf("skipped=%d errors=%d", e.Metrics.MLSkipped.Load(), e.Metrics.MLErrors.Load())
	}
}

func TestRefreshMLValidatesContract(t *testing.T) {
	f := newFakeML(t)
	e, _ := newCascade(t, f, nil)
	if e.MLVersion() == "" {
		t.Fatal("ML must be active after a valid refresh")
	}
	good := f.info.Load().(mlclient.Info)

	bad := good
	bad.Features = append([]string(nil), good.Features...)
	bad.Features[3], bad.Features[4] = bad.Features[4], bad.Features[3]
	f.info.Store(bad)
	if err := e.RefreshML(context.Background()); err == nil {
		t.Fatal("feature order mismatch must be rejected")
	}
	if e.MLVersion() != "" {
		t.Fatal("contract mismatch must disable stage 2")
	}
	r, _ := e.Score(spoofCall("mm-1"))
	if r.Stage != "linear" {
		t.Fatal("with stage 2 disabled the core must use stage 1")
	}

	short := good
	short.Features = good.Features[:5]
	f.info.Store(short)
	if err := e.RefreshML(context.Background()); err == nil {
		t.Fatal("wrong feature count must be rejected")
	}
	for _, th := range []map[string]float64{
		{"review": 0.9, "block": 0.3, "gate": 0.02, "min_signals": 2},
		{"review": 0, "block": 0.9, "gate": 0.02, "min_signals": 2},
		{"review": 0.3, "block": 1.2, "gate": 0.02, "min_signals": 2},
		{"review": 0.3, "block": 0.9, "gate": 2, "min_signals": 2},
	} {
		inf := good
		inf.Thresholds = th
		f.info.Store(inf)
		if err := e.RefreshML(context.Background()); err == nil {
			t.Fatalf("thresholds %v must be rejected", th)
		}
	}
	f.info.Store(good)
	if err := e.RefreshML(context.Background()); err != nil || e.MLVersion() != "cb-test" {
		t.Fatalf("recovery: %v", err)
	}
}

func TestRefreshMLTransientErrorKeepsState(t *testing.T) {
	f := newFakeML(t)
	e, _ := newCascade(t, f, nil)
	f.srv.Close() // ML недоступен во время обновления описания
	if err := e.RefreshML(context.Background()); err == nil {
		t.Fatal("expected an error while ML is down")
	}
	if e.MLVersion() != "cb-test" {
		t.Fatal("a transient failure must not disable a previously validated ML stage")
	}
}

func TestNoMLConfiguredIsNoop(t *testing.T) {
	e, _ := newEngine(t, nil)
	if err := e.RefreshML(context.Background()); err != nil || e.MLVersion() != "" {
		t.Fatal("no ML configured → no-op")
	}
	r, _ := e.Score(spoofCall("n-1"))
	if r.Stage != "linear" {
		t.Fatalf("stage = %s", r.Stage)
	}
}
