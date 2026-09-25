// decision-api — ядро антифрод-pipeline (L1 rules → L2 velocity → внешний scorer).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sanchyous/redflag-antifraud/internal/api"
	"github.com/sanchyous/redflag-antifraud/internal/decider"
	"github.com/sanchyous/redflag-antifraud/internal/rules"
	"github.com/sanchyous/redflag-antifraud/internal/store"
	"github.com/sanchyous/redflag-antifraud/internal/velocity"
)

const version = "0.1.0"

func main() {
	cfg := loadConfig()
	logger := setupLogger(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(logger)

	logger.Info("starting", "service", "decision-api", "version", version, "addr", cfg.Addr)

	ctx := context.Background()

	// Redis — L2. Недоступный Redis на старте не фатален: будет degraded на каждом запросе.
	rdb := redis.NewClient(&redis.Options{
		Addr: cfg.RedisAddr,
		// Быстрый отказ: недоступный Redis не должен держать запрос секунды
		// (дефолт go-redis MaxRetries=3 с dial-timeout — до ~3с на транзакцию).
		MaxRetries:   0,
		DialTimeout:  250 * time.Millisecond,
		ReadTimeout:  500 * time.Millisecond,
		WriteTimeout: 500 * time.Millisecond,
	})

	// Postgres — журнал решений. Пустой DATABASE_URL = журнал отключён.
	var st *store.Store
	if cfg.DatabaseURL != "" {
		var err error
		st, err = store.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			logger.Error("store_open_failed", "err", err.Error())
			os.Exit(1)
		}
		defer st.Close()
		logger.Info("store_connected")
	} else {
		logger.Warn("store_disabled", "reason", "DATABASE_URL not set")
	}

	scorer := &decider.Scorer{
		Rules: rules.Config{
			MaxAmount:         cfg.RulesMaxAmount,
			AllowedCurrencies: splitCSV(cfg.RulesAllowedCurrencies),
			BlockedUsers:      splitCSV(cfg.RulesBlockedUsers),
			BlockedIPs:        splitCSV(cfg.RulesBlockedIPs),
		},
		Vel:       velocity.New(rdb, cfg.VelocityMaxPerUser, cfg.VelocityMaxPerIP, cfg.VelocityWindow),
		ScorerURL: cfg.ScorerURL,
		HTTP:      &http.Client{Timeout: decider.HTTPTimeout},
		FailOpen:  cfg.FailOpen,
		Log:       logger,
	}

	srv := &api.Server{Decider: scorer, Store: st, APIKey: cfg.APIKey, Log: logger}

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		logger.Info("listening")
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen_failed", "err", err.Error())
			os.Exit(1)
		}
	}()

	// Graceful shutdown: SIGTERM из docker stop / systemctl даёт время доработать запросам.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	sig := <-stop
	logger.Info("shutting_down", "signal", sig.String())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown_error", "err", err.Error())
	}
	if err := rdb.Close(); err != nil {
		logger.Warn("redis_close_error", "err", err.Error())
	}
	logger.Info("stopped")
}

type config struct {
	Addr                   string
	RedisAddr              string
	DatabaseURL            string
	ScorerURL              string
	RulesMaxAmount         float64
	RulesAllowedCurrencies string
	RulesBlockedUsers      string
	RulesBlockedIPs        string
	VelocityMaxPerUser     int
	VelocityMaxPerIP       int
	VelocityWindow         time.Duration
	APIKey                 string
	FailOpen               bool
	LogLevel               string
	LogFormat              string
}

func loadConfig() config {
	return config{
		Addr:        env("ADDR", ":8000"),
		RedisAddr:   env("REDIS_ADDR", "127.0.0.1:6379"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		ScorerURL:   os.Getenv("SCORER_URL"),
		APIKey:      os.Getenv("API_KEY"),
		// FAIL_MODE=closed: деградация инфраструктуры эскалирует вердикт до review.
		// Любое другое значение (включая отсутствие) — open.
		FailOpen:           !strings.EqualFold(os.Getenv("FAIL_MODE"), "closed"),
		VelocityMaxPerUser: envInt("VELOCITY_MAX_PER_USER", 10),
		VelocityMaxPerIP:   envInt("VELOCITY_MAX_PER_IP", 30),
		VelocityWindow:     time.Duration(envInt("VELOCITY_WINDOW_SEC", 60)) * time.Second,
		LogLevel:           env("LOG_LEVEL", "info"),
		LogFormat:          env("LOG_FORMAT", "text"),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func setupLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler
	if strings.ToLower(format) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}
