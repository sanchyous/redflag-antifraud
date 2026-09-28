// Package api — HTTP-слой: маршруты, request_id, auth, скоринг вызовов, метрики.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/callrec"
	"github.com/sanchyous/redflag-antifraud/internal/engine"
	"github.com/sanchyous/redflag-antifraud/internal/explain"
	"github.com/sanchyous/redflag-antifraud/internal/journal"
	"github.com/sanchyous/redflag-antifraud/internal/protect"
	"github.com/sanchyous/redflag-antifraud/internal/store"
)

const (
	maxBodyBytes  = 32 << 10 // один вызов
	maxBatchBytes = 4 << 20  // пакет
	maxBatchCalls = 1000
)

// Server — HTTP-сервер ядра.
type Server struct {
	Engine   *engine.Engine
	Journal  *journal.Journal // nil — журнал отключён
	Store    *store.Store     // nil — /v1/calls/recent недоступен
	APIKey   string           // пусто — auth отключён (dev)
	FailOpen bool             // при сбое скоринга: true → allow, false → review
	Log      *slog.Logger

	lat    latencyHist
	panics atomic.Uint64
}

// Routes собирает маршруты с middleware.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /docs", s.handleDocs)
	mux.HandleFunc("GET /openapi.yaml", s.handleOpenAPI)
	mux.Handle("POST /v1/calls/score", s.protect(http.HandlerFunc(s.handleScore)))
	mux.Handle("POST /v1/calls/score/batch", s.protect(http.HandlerFunc(s.handleBatch)))
	mux.Handle("GET /v1/calls/recent", s.protect(http.HandlerFunc(s.handleRecent)))
	return s.withRequestID(s.withLogging(s.withRecover(mux)))
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	m := s.Engine.Model()
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "model_version": m.Version})
}

// scoreSafe скорит вызов, не давая панике уйти наружу. При панике применяется FAIL_MODE;
// экстренные службы при любом сбое получают allow.
func (s *Server) scoreSafe(c *callrec.Call) (resp engine.Response, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			s.Log.Error("score_panic", "call_id", c.CallID, "panic", fmt.Sprint(rec))
			s.panics.Add(1) // не трогаем движок: он мог быть причиной паники
			resp = fallback(c, s.FailOpen)
			err = nil
		}
	}()
	return s.Engine.Score(c)
}

func fallback(c *callrec.Call, failOpen bool) engine.Response {
	r := engine.Response{CallID: c.CallID, Reasons: []explain.Reason{}}
	switch {
	case protect.IsEmergencyRaw(c.Callee) || protect.IsEmergencyRaw(c.Caller):
		r.Decision = "allow"
		r.SafeClass = protect.Emergency.String()
	case failOpen:
		r.Decision = "allow"
		r.Reasons = []explain.Reason{{Factor: "internal_error", Effect: "raises", Text: "сбой скоринга; применён режим FAIL_MODE=open"}}
	default:
		r.Decision = "review"
		r.Reasons = []explain.Reason{{Factor: "internal_error", Effect: "raises", Text: "сбой скоринга; применён режим FAIL_MODE=closed"}}
	}
	return r
}

func (s *Server) record(resp *engine.Response) {
	if s.Journal == nil || !s.Journal.Wants(resp.Decision, resp.CallID) {
		return
	}
	reasons, _ := json.Marshal(resp.Reasons)
	s.Journal.Add(store.Record{
		CallID: resp.CallID, CallerMasked: resp.Caller.Masked, CalleeMasked: resp.Callee.Masked,
		Decision: resp.Decision, Score: resp.Score, Reasons: reasons, Signals: resp.Signals,
		SafeClass: resp.SafeClass, ModelVersion: resp.ModelVersion, NumplanVersion: resp.NumplanVersion,
		LatencyUS: resp.LatencyUS, CreatedAt: time.Now(),
	})
}

func (s *Server) handleScore(w http.ResponseWriter, r *http.Request) {
	reqID := requestIDFrom(r.Context())
	var c callrec.Call
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		s.badRequest(w, reqID, "invalid_json")
		return
	}
	start := time.Now()
	resp, err := s.scoreSafe(&c)
	s.lat.observe(time.Since(start))
	if err != nil {
		var ve *engine.ValidationError
		if errors.As(err, &ve) {
			s.badRequest(w, reqID, ve.Codes[0])
			return
		}
		s.Log.ErrorContext(r.Context(), "score_failed", "request_id", reqID, "err", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	s.record(&resp)
	writeJSON(w, http.StatusOK, resp)
}

type batchRequest struct {
	Calls []callrec.Call `json:"calls"`
}

type batchItem struct {
	CallID string           `json:"call_id"`
	Result *engine.Response `json:"result,omitempty"`
	Error  string           `json:"error,omitempty"`
}

// handleBatch скорит пакет по порядку (порядок важен для окон); ошибка одного вызова не роняет пакет.
func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	reqID := requestIDFrom(r.Context())
	var req batchRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxBatchBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.badRequest(w, reqID, "invalid_json")
		return
	}
	if len(req.Calls) == 0 {
		s.badRequest(w, reqID, "calls_required")
		return
	}
	if len(req.Calls) > maxBatchCalls {
		s.badRequest(w, reqID, "batch_too_large")
		return
	}
	items := make([]batchItem, len(req.Calls))
	for i := range req.Calls {
		c := &req.Calls[i]
		start := time.Now()
		resp, err := s.scoreSafe(c)
		s.lat.observe(time.Since(start))
		items[i].CallID = c.CallID
		if err != nil {
			var ve *engine.ValidationError
			if errors.As(err, &ve) {
				items[i].Error = ve.Codes[0]
			} else {
				items[i].Error = "internal"
			}
			continue
		}
		s.record(&resp)
		items[i].Result = &resp
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": items})
}

func (s *Server) handleRecent(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "store_disabled"})
		return
	}
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 200 {
			s.badRequest(w, requestIDFrom(r.Context()), "invalid_limit")
			return
		}
		limit = n
	}
	decision := r.URL.Query().Get("decision")
	if decision != "" && decision != "allow" && decision != "review" && decision != "block" {
		s.badRequest(w, requestIDFrom(r.Context()), "invalid_decision")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	entries, err := s.Store.Recent(ctx, limit, decision)
	if err != nil {
		s.Log.ErrorContext(r.Context(), "recent_query_failed", "err", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if entries == nil {
		entries = []store.Entry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries})
}

func (s *Server) badRequest(w http.ResponseWriter, reqID, code string) {
	w.Header().Set("X-Request-Id", reqID)
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code, "request_id": reqID})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
