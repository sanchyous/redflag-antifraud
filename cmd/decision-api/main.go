// decision-api — ядро антифрод-скоринга вызовов по метаданным сигнализации.
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

	"github.com/sanchyous/redflag-antifraud/internal/api"
	"github.com/sanchyous/redflag-antifraud/internal/decide"
	"github.com/sanchyous/redflag-antifraud/internal/engine"
	"github.com/sanchyous/redflag-antifraud/internal/journal"
	"github.com/sanchyous/redflag-antifraud/internal/mlclient"
	"github.com/sanchyous/redflag-antifraud/internal/numplan"
	"github.com/sanchyous/redflag-antifraud/internal/protect"
	"github.com/sanchyous/redflag-antifraud/internal/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/store"
	"github.com/sanchyous/redflag-antifraud/internal/window"
)

const version = "1.0.0"

func main() {
	cfg := loadConfig()
	logger := setupLogger(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(logger)
	logger.Info("starting", "service", "decision-api", "version", version, "addr", cfg.Addr)

	ctx := context.Background()

	// Справочник нумерации: явная ошибка конфигурации — fail-fast; не задан — работаем без регионов.
	var plan *numplan.Plan
	if cfg.NumplanDir != "" {
		t0 := time.Now()
		var err error
		plan, err = numplan.LoadDir(cfg.NumplanDir)
		if err != nil {
			logger.Error("numplan_load_failed", "dir", cfg.NumplanDir, "err", err.Error())
			os.Exit(1)
		}
		logger.Info("numplan_loaded", "ranges", plan.Size(), "version", plan.Version,
			"overlaps", plan.Stats.Overlaps, "skipped", plan.Stats.Skipped, "took_ms", time.Since(t0).Milliseconds())
	} else {
		logger.Warn("numplan_disabled", "reason", "NUMPLAN_DIR not set: region/operator features are off")
	}

	classifier, err := loadAllowlist(cfg.AllowlistFile, logger)
	if err != nil {
		logger.Error("allowlist_load_failed", "err", err.Error())
		os.Exit(1)
	}

	model, err := loadModel(cfg.ModelFile)
	if err != nil {
		logger.Error("model_load_failed", "file", cfg.ModelFile, "err", err.Error())
		os.Exit(1)
	}
	logger.Info("model_ready", "version", model.Version, "review", model.Review, "block", model.Block)

	// Стадия 2 каскада — ML-сервис (Python). Не задан ML_URL — работает только стадия 1.
	var mlc *mlclient.Client
	if cfg.MLURL != "" {
		mlc, err = mlclient.New(mlclient.Config{
			BaseURL: cfg.MLURL, APIKey: cfg.MLAPIKey, Timeout: time.Duration(cfg.MLTimeoutMS) * time.Millisecond,
			BreakerFailures: cfg.MLBreakerFails, BreakerCooldown: time.Duration(cfg.MLBreakerCooldownSec) * time.Second,
		})
		if err != nil {
			logger.Error("ml_client_init_failed", "err", err.Error())
			os.Exit(1)
		}
	} else {
		logger.Warn("ml_disabled", "reason", "ML_URL not set: only the linear stage is used")
	}

	eng, err := engine.New(engine.Config{
		ML:         mlc,
		OnMLError:  func(err error) { logger.Warn("ml_refresh_failed", "err", err.Error()) },
		Plan:       plan,
		Classifier: classifier,
		Model:      model,
		Policy: decide.Policy{
			Review: float32(cfg.ReviewThreshold), Block: float32(cfg.BlockThreshold), MinStrong: cfg.MinStrong,
		},
		MaxFutureSkew: time.Duration(cfg.MaxFutureSkewSec) * time.Second,
		Window:        window.Config{MaxEvents: cfg.WindowMaxEvents, MaxNumbers: cfg.WindowMaxNumbers, ShortSec: cfg.ShortCallSec},
	})
	if err != nil {
		logger.Error("engine_init_failed", "err", err.Error())
		os.Exit(1)
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	if mlc != nil {
		// ML может подняться позже ядра: недоступность на старте не фатальна, обновление — в фоне.
		rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		if err := eng.RefreshML(rctx); err != nil {
			logger.Warn("ml_unavailable_at_start", "err", err.Error())
		} else {
			logger.Info("ml_ready", "version", eng.MLVersion())
		}
		cancel()
	}
	go eng.Run(runCtx, time.Duration(cfg.FanEverySec)*time.Second, 5*time.Minute)

	// Postgres — журнал решений. Пустой DATABASE_URL = журнал отключён.
	var st *store.Store
	var jr *journal.Journal
	if cfg.DatabaseURL != "" {
		st, err = store.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			logger.Error("store_open_failed", "err", err.Error())
			os.Exit(1)
		}
		defer st.Close()
		jr = journal.New(st, journal.Config{AllowSample: cfg.JournalAllowSample}, logger)
		defer jr.Close()
		logger.Info("store_connected")
	} else {
		logger.Warn("store_disabled", "reason", "DATABASE_URL not set")
	}

	srv := &api.Server{Engine: eng, Journal: jr, Store: st, APIKey: cfg.APIKey, FailOpen: cfg.FailOpen, Log: logger}
	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		logger.Info("listening")
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen_failed", "err", err.Error())
			os.Exit(1)
		}
	}()

	// SIGHUP — горячая перезагрузка модели из MODEL_FILE; SIGTERM/SIGINT — корректная остановка.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigs {
		if sig == syscall.SIGHUP {
			if cfg.ModelFile == "" {
				logger.Warn("reload_skipped", "reason", "MODEL_FILE not set")
				continue
			}
			m, err := loadModel(cfg.ModelFile)
			if err != nil {
				logger.Error("model_reload_failed", "err", err.Error())
				continue
			}
			eng.SetModel(m)
			logger.Info("model_reloaded", "version", m.Version)
			continue
		}
		logger.Info("shutting_down", "signal", sig.String())
		break
	}

	cancelRun()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown_error", "err", err.Error())
	}
	logger.Info("stopped")
}

func loadModel(path string) (*scoring.Model, error) {
	if path == "" {
		return scoring.Prior(), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return scoring.Load(f)
}

func loadAllowlist(path string, log *slog.Logger) (*protect.Classifier, error) {
	c := protect.New()
	if path == "" {
		return c, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	n, bad := c.LoadAllowlist(f)
	for _, b := range bad {
		log.Warn("allowlist_bad_entry", "entry", b)
	}
	log.Info("allowlist_loaded", "entries", n, "bad", len(bad))
	return c, nil
}

type config struct {
	Addr                 string
	DatabaseURL          string
	APIKey               string
	FailOpen             bool
	NumplanDir           string
	AllowlistFile        string
	ModelFile            string
	ReviewThreshold      float64
	BlockThreshold       float64
	MinStrong            int
	WindowMaxEvents      int
	WindowMaxNumbers     int
	ShortCallSec         int
	MaxFutureSkewSec     int
	FanEverySec          int
	JournalAllowSample   float64
	MLURL                string
	MLAPIKey             string
	MLTimeoutMS          int
	MLBreakerFails       int
	MLBreakerCooldownSec int
	LogLevel             string
	LogFormat            string
}

func loadConfig() config {
	return config{
		Addr:        env("ADDR", ":8000"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		APIKey:      os.Getenv("API_KEY"),
		// FAIL_MODE=closed: сбой скоринга эскалирует вердикт до review; иначе — open (allow).
		FailOpen:      !strings.EqualFold(os.Getenv("FAIL_MODE"), "closed"),
		NumplanDir:    os.Getenv("NUMPLAN_DIR"),
		AllowlistFile: os.Getenv("ALLOWLIST_FILE"),
		ModelFile:     os.Getenv("MODEL_FILE"),
		// 0 — взять порог из файла модели.
		ReviewThreshold:      envFloat("REVIEW_THRESHOLD", 0),
		BlockThreshold:       envFloat("BLOCK_THRESHOLD", 0),
		MinStrong:            envInt("BLOCK_MIN_SIGNALS", 2),
		WindowMaxEvents:      envInt("WINDOW_MAX_EVENTS", 512),
		WindowMaxNumbers:     envInt("WINDOW_MAX_NUMBERS", 4_000_000),
		ShortCallSec:         envInt("SHORT_CALL_SEC", 10),
		MaxFutureSkewSec:     envInt("MAX_FUTURE_SKEW_SEC", 0),
		FanEverySec:          envInt("FAN_REFRESH_SEC", 30),
		JournalAllowSample:   envFloat("JOURNAL_ALLOW_SAMPLE", 0.01),
		MLURL:                os.Getenv("ML_URL"),
		MLAPIKey:             os.Getenv("ML_API_KEY"),
		MLTimeoutMS:          envInt("ML_TIMEOUT_MS", 50),
		MLBreakerFails:       envInt("ML_BREAKER_FAILS", 5),
		MLBreakerCooldownSec: envInt("ML_BREAKER_COOLDOWN_SEC", 10),
		LogLevel:             env("LOG_LEVEL", "info"),
		LogFormat:            env("LOG_FORMAT", "text"),
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
