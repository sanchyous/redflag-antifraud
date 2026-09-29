// decision-api — ядро антифрод-скоринга вызовов по метаданным сигнализации.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof" // профилирование включается только явно (PPROF_ADDR), см. startPprof
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/api"
	"github.com/sanchyous/redflag-antifraud/internal/decision/decide"
	"github.com/sanchyous/redflag-antifraud/internal/decision/engine"
	"github.com/sanchyous/redflag-antifraud/internal/decision/mlclient"
	"github.com/sanchyous/redflag-antifraud/internal/decision/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/detection/protect"
	"github.com/sanchyous/redflag-antifraud/internal/detection/window"
	"github.com/sanchyous/redflag-antifraud/internal/platform/journal"
	"github.com/sanchyous/redflag-antifraud/internal/platform/logx"
	"github.com/sanchyous/redflag-antifraud/internal/platform/store"
	"github.com/sanchyous/redflag-antifraud/internal/platform/telemetry"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/numplan"
)

// version переопределяется при сборке: -ldflags "-X main.version=...".
var version = "1.1.0"

func main() {
	cfg := loadConfig()

	// Логирование: формат по умолчанию — читаемый на терминале и JSON вне его. Повторяющиеся события горячего пути
	// (решения) ограничиваются по частоте, предупреждения и ошибки — никогда.
	base := logx.New(logx.Config{Level: cfg.LogLevel, Format: cfg.LogFormat, Service: "decision-api", Version: version})
	logger := slog.New(logx.RateLimit(base.Handler(), cfg.LogRatePerSec))
	slog.SetDefault(logger)
	log := logx.Component(logger, "main")

	log.Info("starting", "addr", cfg.Addr, "go", runtime.Version(), "cpus", runtime.NumCPU(), "gomaxprocs", runtime.GOMAXPROCS(0))
	log.Info("config", "fail_mode", failMode(cfg.FailOpen), "auth", cfg.APIKey != "", "database", cfg.DatabaseURL != "",
		"ml", cfg.MLURL != "", "numplan", cfg.NumplanDir != "", "allowlist", cfg.AllowlistFile != "", "log_decisions", cfg.LogDecisions,
		"window_max_events", cfg.WindowMaxEvents, "window_max_numbers", cfg.WindowMaxNumbers)
	if cfg.APIKey == "" {
		log.Warn("api_unprotected", "reason", "API_KEY is empty: anyone who can reach the port can call the API and read the dashboard data")
	}

	ctx := context.Background()
	startPprof(cfg.PprofAddr, log)

	// Справочник нумерации: явная ошибка конфигурации — fail-fast; не задан — работаем без регионов.
	var plan *numplan.Plan
	if cfg.NumplanDir != "" {
		t0 := time.Now()
		var err error
		plan, err = numplan.LoadDir(cfg.NumplanDir)
		if err != nil {
			log.Error("numplan_load_failed", "dir", cfg.NumplanDir, "err", err.Error())
			os.Exit(1)
		}
		log.Info("numplan_loaded", "ranges", plan.Size(), "regions", plan.RegionCount(), "version", plan.Version,
			"overlaps", plan.Stats.Overlaps, "skipped", plan.Stats.Skipped, "took", time.Since(t0).Round(time.Millisecond).String())
	} else {
		log.Warn("numplan_disabled", "reason", "NUMPLAN_DIR not set: region and operator features are off")
	}

	classifier, err := loadAllowlist(cfg.AllowlistFile, log)
	if err != nil {
		log.Error("allowlist_load_failed", "err", err.Error())
		os.Exit(1)
	}

	model, err := loadModel(cfg.ModelFile)
	if err != nil {
		log.Error("model_load_failed", "file", cfg.ModelFile, "err", err.Error())
		os.Exit(1)
	}
	log.Info("model_ready", "version", model.Version, "review", model.Review, "block", model.Block, "file", cfg.ModelFile)

	// Стадия 2 каскада — ML-сервис (Python). Не задан ML_URL — работает только стадия 1.
	var mlc *mlclient.Client
	if cfg.MLURL != "" {
		mlc, err = mlclient.New(mlclient.Config{
			BaseURL: cfg.MLURL, APIKey: cfg.MLAPIKey, Timeout: time.Duration(cfg.MLTimeoutMS) * time.Millisecond,
			BreakerFailures: cfg.MLBreakerFails, BreakerCooldown: time.Duration(cfg.MLBreakerCooldownSec) * time.Second,
			Log: logx.Component(logger, "ml"),
		})
		if err != nil {
			log.Error("ml_client_init_failed", "err", err.Error())
			os.Exit(1)
		}
	} else {
		log.Warn("ml_disabled", "reason", "ML_URL not set: only the linear stage is used")
	}

	eng, err := engine.New(engine.Config{
		ML:         mlc,
		Log:        logger,
		OnMLError:  func(err error) { log.Warn("ml_refresh_failed", "err", err.Error()) },
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
		log.Error("engine_init_failed", "err", err.Error())
		os.Exit(1)
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	if mlc != nil {
		// ML может подняться позже ядра: недоступность на старте не фатальна, обновление — в фоне.
		rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		if err := eng.RefreshML(rctx); err != nil {
			log.Warn("ml_unavailable_at_start", "err", err.Error())
		} else if err := eng.WarmupML(rctx); err != nil {
			log.Warn("ml_warmup_failed", "err", err.Error())
		}
		cancel()
	}
	go eng.Run(runCtx, time.Duration(cfg.FanEverySec)*time.Second, 5*time.Minute)

	// Телеметрия для панели: ряды по секундам и минутам в памяти, свёртка фоном.
	tel := telemetry.New(nil)
	stopTel := make(chan struct{})
	go tel.Run(stopTel)
	persistDone := make(chan struct{})
	close(persistDone) // без Postgres сохранять нечего

	// Postgres — журнал решений. Пустой DATABASE_URL = журнал отключён.
	var st *store.Store
	var jr *journal.Journal
	if cfg.DatabaseURL != "" {
		st, err = store.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			log.Error("store_open_failed", "err", err.Error())
			os.Exit(1)
		}
		defer st.Close()
		jr = journal.New(st, journal.Config{AllowSample: cfg.JournalAllowSample}, logx.Component(logger, "journal"))
		defer jr.Close()
		log.Info("store_connected", "journal_allow_sample", cfg.JournalAllowSample)

		// Панель не должна обнуляться при перезапуске: поднимаем сутки минутных агрегатов и последние рискованные
		// решения, дальше агрегаты сохраняются в фоне.
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if rows, err := st.LoadMinutes(rctx, time.Now().Add(-24*time.Hour).Unix()); err != nil {
			log.Warn("telemetry_restore_failed", "err", err.Error())
		} else if evs, err := st.RiskyEvents(rctx, 1000); err != nil {
			log.Warn("telemetry_restore_failed", "err", err.Error())
		} else {
			tel.RestoreEvents(evs)
			log.Info("telemetry_restored", "minutes", tel.Restore(rows), "events", len(evs))
		}
		cancel()
		persistDone = make(chan struct{})
		go func() {
			defer close(persistDone)
			tel.Persist(runCtx, st, 15*time.Second, func(err error) { log.Warn("telemetry_save_failed", "err", err.Error()) })
		}()
	} else {
		log.Warn("store_disabled", "reason", "DATABASE_URL not set: decisions are not journaled")
	}

	srv := &api.Server{
		Engine: eng, Journal: jr, Store: st, APIKey: cfg.APIKey, FailOpen: cfg.FailOpen,
		Log: logx.Component(logger, "api"), Version: version, LogDecisions: cfg.LogDecisions, Tel: tel,
	}
	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logx.Component(logger, "http").Handler(), slog.LevelWarn),
	}
	go func() {
		log.Info("listening", "addr", cfg.Addr, "ui", "/ui/", "docs", "/docs")
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen_failed", "err", err.Error())
			os.Exit(1)
		}
	}()

	// SIGHUP — горячая перезагрузка модели из MODEL_FILE; SIGTERM/SIGINT — корректная остановка.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigs {
		if sig == syscall.SIGHUP {
			if cfg.ModelFile == "" {
				log.Warn("reload_skipped", "reason", "MODEL_FILE not set")
				continue
			}
			m, err := loadModel(cfg.ModelFile)
			if err != nil {
				log.Error("model_reload_failed", "err", err.Error())
				continue
			}
			eng.SetModel(m)
			log.Info("model_reloaded", "version", m.Version, "review", m.Review, "block", m.Block)
			continue
		}
		log.Info("shutting_down", "signal", sig.String())
		break
	}

	cancelRun()
	<-persistDone // последнее сохранение телеметрии до закрытия соединения с БД
	close(stopTel)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown_error", "err", err.Error())
	}
	log.Info("stopped", "uptime", time.Since(tel.Started()).Round(time.Second).String())
}

// startPprof поднимает отладочный сервер профилирования. Выключен по умолчанию; допустим только адрес loopback:
// профили раскрывают внутренности процесса и не должны быть доступны из сети.
func startPprof(addr string, log *slog.Logger) {
	if addr == "" {
		return
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		log.Error("pprof_refused", "addr", addr, "reason", "PPROF_ADDR must be a loopback address such as 127.0.0.1:6060")
		return
	}
	go func() {
		log.Warn("pprof_enabled", "addr", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Error("pprof_failed", "err", err.Error())
		}
	}()
}

func failMode(open bool) string {
	if open {
		return "open"
	}
	return "closed"
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
	log.Info("allowlist_loaded", "entries", n, "bad", len(bad), "file", path)
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
	LogDecisions         string
	LogRatePerSec        int
	PprofAddr            string
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
		LogFormat:            os.Getenv("LOG_FORMAT"), // пусто: pretty на терминале, json иначе
		LogDecisions:         env("LOG_DECISIONS", "flagged"),
		LogRatePerSec:        envInt("LOG_RATE_PER_SEC", 200),
		PprofAddr:            os.Getenv("PPROF_ADDR"),
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
