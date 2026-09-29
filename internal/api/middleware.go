package api

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/platform/logx"
)

type ctxKeyRequestID struct{}

func requestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRequestID{}).(string); ok {
		return v
	}
	return ""
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		// request_id кладём и в контекст логирования: любая запись с этим контекстом получит поле автоматически
		ctx := logx.WithRequestID(context.WithValue(r.Context(), ctxKeyRequestID{}, id), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Log.Error("panic_recovered", "request_id", requestIDFrom(r.Context()),
					"panic", rec, "path", r.URL.Path)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// statusRecorder запоминает код ответа для access-лога.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

var recPool = sync.Pool{New: func() any { return new(statusRecorder) }}

// withLogging — access-лог каждого запроса: одна строка, все поля структурой.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := recPool.Get().(*statusRecorder)
		rec.ResponseWriter, rec.status = w, http.StatusOK
		defer func() { rec.ResponseWriter = nil; recPool.Put(rec) }()
		next.ServeHTTP(rec, r)
		// Горячий путь скоринга при большом потоке не должен писать строку в лог на каждый
		// успешный запрос: 2xx по /v1/calls/* идут на уровне debug, всё остальное — info.
		lvl := slog.LevelInfo
		if rec.status < 400 && strings.HasPrefix(r.URL.Path, "/v1/calls/score") {
			lvl = slog.LevelDebug
		}
		// Уровень проверяется ДО сборки аргументов: упаковка полей и разбор адреса клиента стоят аллокаций,
		// а отброшенная запись не должна тратить их на каждом запросе горячего пути.
		if !s.Log.Enabled(r.Context(), lvl) {
			return
		}
		s.Log.Log(r.Context(), lvl, "http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_ip", remoteIP(r),
		)
	})
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// newRequestID — 16 шестнадцатеричных знаков. Идентификатор нужен для сопоставления записей, а не для защиты,
// поэтому берётся быстрый генератор (без системного вызова и лишних аллокаций).
func newRequestID() string {
	const hexd = "0123456789abcdef"
	v := rand.Uint64()
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = hexd[v&0xF]
		v >>= 4
	}
	return string(b[:])
}

// protect включает проверку X-API-Key (constant-time), если ключ задан.
// Пустой ключ — dev-режим без auth.
func (s *Server) protect(next http.Handler) http.Handler {
	if s.APIKey == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), []byte(s.APIKey)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
