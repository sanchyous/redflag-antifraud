package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decision/engine"
	"github.com/sanchyous/redflag-antifraud/internal/decision/mlclient"
)

func newMLServer(t *testing.T, withReport bool, hits *atomic.Int32) *Server {
	t.Helper()
	ml := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/report":
			hits.Add(1)
			if !withReport {
				http.Error(w, `{"detail":"report_not_found"}`, http.StatusNotFound)
				return
			}
			_, _ = io.WriteString(w, `{"schema":1,"model":{"version":"m1"}}`)
		case "/v1/stats":
			_, _ = io.WriteString(w, `{"requests":7}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ml.Close)
	c, err := mlclient.New(mlclient.Config{BaseURL: ml.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	eng, err := engine.New(engine.Config{ML: c, Plan: testPlan(t), Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	return &Server{Engine: eng, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), FailOpen: true}
}

func TestMLReportProxyAndCache(t *testing.T) {
	var hits atomic.Int32
	h := newMLServer(t, true, &hits).Routes()
	for i := 0; i < 3; i++ {
		rr := do(t, h, "GET", "/v1/ml/report", "")
		if rr.Code != 200 || rr.Body.String() != `{"schema":1,"model":{"version":"m1"}}` {
			t.Fatalf("отчёт: %d %q", rr.Code, rr.Body.String())
		}
	}
	if hits.Load() != 1 {
		t.Errorf("отчёт должен кэшироваться: обращений к ML-сервису %d, ожидалось 1", hits.Load())
	}
	if rr := do(t, h, "GET", "/v1/ml/service", ""); rr.Code != 200 || rr.Body.String() != `{"requests":7}` {
		t.Errorf("статистика сервиса: %d %q", rr.Code, rr.Body.String())
	}
}

func TestMLReportMissing(t *testing.T) {
	var hits atomic.Int32
	rr := do(t, newMLServer(t, false, &hits).Routes(), "GET", "/v1/ml/report", "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("нет отчёта: код %d, ожидался 404", rr.Code)
	}
}

func TestMLReportWithoutML(t *testing.T) {
	rr := do(t, newServer(t, nil).Routes(), "GET", "/v1/ml/report", "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("ML не подключён: код %d, ожидался 503", rr.Code)
	}
}
