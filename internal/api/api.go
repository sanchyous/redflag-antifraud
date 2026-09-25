// Package api — HTTP-слой: маршруты, request_id, доступ к логам каждого запроса.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decider"
	"github.com/sanchyous/redflag-antifraud/internal/decision"
	"github.com/sanchyous/redflag-antifraud/internal/store"
)

const maxBodyBytes = 64 << 10 // 64KB

type Server struct {
	Decider *decider.Scorer
	Store   *store.Store // может быть nil — журнал отключён
	APIKey  string       // пусто — X-API-Key auth отключён (dev-режим)
	Log     *slog.Logger
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /docs", s.handleDocs)
	mux.HandleFunc("GET /openapi.yaml", s.handleOpenAPI)
	mux.Handle("POST /v1/decisions", s.protect(http.HandlerFunc(s.handleDecision)))
	mux.Handle("GET /v1/decisions/recent", s.protect(http.HandlerFunc(s.handleRecent)))
	return s.withRequestID(s.withLogging(s.withRecover(mux)))
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request) {
	reqID := requestIDFrom(r.Context())

	var t decision.Txn
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		s.badRequest(w, reqID, "invalid_json")
		return
	}
	if errs := t.Validate(); len(errs) > 0 {
		s.badRequest(w, reqID, errs[0])
		return
	}

	// Отсутствующий ts — серверное время приёма (клиентские часы не доверяем).
	if t.TS.IsZero() {
		t.TS = time.Now().UTC()
	}

	verdict := s.Decider.Evaluate(r.Context(), t, reqID)

	// Журнал — некритический путь: ошибка пишется в лог, ответ клиенту не портим.
	if s.Store != nil {
		saveCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		err := s.Store.Save(saveCtx, store.Record{
			RequestID:     reqID,
			TransactionID: t.TransactionID,
			UserID:        t.UserID,
			Amount:        t.Amount,
			Currency:      t.Currency,
			IP:            t.IP,
			Decision:      verdict.Decision,
			Reasons:       verdict.Reasons,
			LatencyMS:     verdict.LatencyMS,
		})
		cancel()
		if err != nil {
			s.Log.ErrorContext(r.Context(), "decision_save_failed",
				"request_id", reqID, "transaction_id", t.TransactionID, "err", err.Error())
		}
	}

	writeJSON(w, http.StatusOK, verdict)
}

func (s *Server) handleRecent(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "store_disabled"})
		return
	}
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			s.badRequest(w, requestIDFrom(r.Context()), "invalid_limit")
			return
		}
		limit = n
	}
	entries, err := s.Store.Recent(r.Context(), limit)
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
