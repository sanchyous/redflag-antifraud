package api

import (
	"errors"
	"io/fs"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decision/engine"
	"github.com/sanchyous/redflag-antifraud/internal/decision/explain"
	"github.com/sanchyous/redflag-antifraud/internal/decision/mlclient"
	"github.com/sanchyous/redflag-antifraud/internal/platform/telemetry"
	"github.com/sanchyous/redflag-antifraud/web"
)

// decisionIndex переводит текстовое решение в индекс телеметрии.
func decisionIndex(d string) int {
	switch d {
	case "review":
		return telemetry.Review
	case "block":
		return telemetry.Block
	}
	return telemetry.Allow
}

// observe передаёт итог скоринга в телеметрию; рискованные решения попадают ещё и в список событий.
func (s *Server) observe(resp *engine.Response) {
	stage := telemetry.StageLinear
	if resp.Stage == "ml" {
		stage = telemetry.StageML
	}
	s.Tel.Observe(telemetry.Sample{
		Decision: decisionIndex(resp.Decision), Stage: stage, LatencyUS: resp.LatencyUS,
		Emergency: resp.SafeClass == "emergency", Duplicate: resp.Duplicate, RuleFloor: resp.RuleFloor, Suppressed: resp.BlockSuppressed,
	})
	if resp.Decision == "allow" {
		return
	}
	ev := telemetry.Event{
		Time: time.Now(), CallID: resp.CallID, Decision: resp.Decision, Score: resp.Score, Summary: resp.Summary, Stage: resp.Stage,
		Signals: resp.Signals, Caller: resp.Caller.Masked, Callee: resp.Callee.Masked,
		CallerRegion: resp.Caller.Region, CalleeRegion: resp.Callee.Region,
		RuleFloor: resp.RuleFloor, Suppressed: resp.BlockSuppressed, SafeClass: resp.SafeClass, LatencyUS: resp.LatencyUS,
		Reasons: briefReasons(resp.Reasons),
	}
	if ev.Signals == nil {
		ev.Signals = []string{}
	}
	s.Tel.RecordEvent(ev)
}

func briefReasons(rs []explain.Reason) []telemetry.Reason {
	out := make([]telemetry.Reason, 0, len(rs))
	for _, r := range rs {
		out = append(out, telemetry.Reason{Factor: r.Factor, Text: r.Text, Contribution: r.Contribution, Effect: r.Effect})
	}
	return out
}

type statusResponse struct {
	Service struct {
		Name      string  `json:"name"`
		Version   string  `json:"version"`
		UptimeSec float64 `json:"uptime_sec"`
		GoVersion string  `json:"go_version"`
		Goroutine int     `json:"goroutines"`
		CPUs      int     `json:"cpus"`
		HeapMB    float64 `json:"heap_mb"`
		GCPauseMS float64 `json:"gc_pause_ms"`
	} `json:"service"`
	Engine  engine.Info `json:"engine"`
	Journal struct {
		Enabled bool   `json:"enabled"`
		Written uint64 `json:"written"`
		Dropped uint64 `json:"dropped"`
		Failed  uint64 `json:"failed"`
	} `json:"journal"`
	Store struct {
		Enabled bool `json:"enabled"`
	} `json:"store"`
	Config struct {
		FailOpen bool `json:"fail_open"`
		Auth     bool `json:"auth"`
	} `json:"config"`
	Totals struct {
		Allow      uint64 `json:"allow"`
		Review     uint64 `json:"review"`
		Block      uint64 `json:"block"`
		Linear     uint64 `json:"linear"`
		ML         uint64 `json:"ml"`
		Emergency  uint64 `json:"emergency"`
		Errors     uint64 `json:"errors"`
		Duplicates uint64 `json:"duplicates"`
		RuleFloors uint64 `json:"rule_floors"`
		MLCalls    uint64 `json:"ml_calls"`
		MLErrors   uint64 `json:"ml_errors"`
		MLSkipped  uint64 `json:"ml_skipped"`
	} `json:"totals"`
}

// handleStatus — сводка состояния для панели: сервис, движок, журнал, счётчики.
func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	var st statusResponse
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	st.Service.Name, st.Service.Version = "decision-api", s.Version
	st.Service.UptimeSec = time.Since(s.Tel.Started()).Seconds()
	st.Service.GoVersion, st.Service.Goroutine, st.Service.CPUs = runtime.Version(), runtime.NumGoroutine(), runtime.NumCPU()
	st.Service.HeapMB = float64(ms.HeapAlloc) / (1 << 20)
	if ms.NumGC > 0 {
		st.Service.GCPauseMS = float64(ms.PauseNs[(ms.NumGC+255)%256]) / 1e6
	}
	st.Engine = s.Engine.Info()
	st.Store.Enabled = s.Store != nil
	if s.Journal != nil {
		st.Journal.Enabled = true
		st.Journal.Written, st.Journal.Dropped, st.Journal.Failed = s.Journal.Written.Load(), s.Journal.Dropped.Load(), s.Journal.Failed.Load()
	}
	st.Config.FailOpen, st.Config.Auth = s.FailOpen, s.APIKey != ""
	m, tot := &s.Engine.Metrics, s.Tel.Totals()
	st.Totals.Allow, st.Totals.Review, st.Totals.Block = tot.Allow, tot.Review, tot.Block // телеметрия переживает перезапуск, счётчики движка — нет
	st.Totals.Linear, st.Totals.ML = tot.Linear, tot.ML
	st.Totals.Emergency, st.Totals.Errors = tot.Emergency, tot.Errors+m.Errors.Load()
	st.Totals.Duplicates, st.Totals.RuleFloors = m.Duplicates.Load(), m.RuleFloors.Load()
	st.Totals.MLCalls, st.Totals.MLErrors, st.Totals.MLSkipped = m.MLCalls.Load(), m.MLErrors.Load(), m.MLSkipped.Load()
	writeJSON(w, http.StatusOK, st)
}

// queryInt читает целый параметр запроса с границами; пусто или мусор — значение по умолчанию.
func queryInt(r *http.Request, name string, def, lo, hi int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return def
	}
	return max(lo, min(hi, v))
}

// handleStats — временные ряды и итоги за окно (window — секунды, points — число точек).
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	window := queryInt(r, "window", 900, 60, 86400)
	points := queryInt(r, "points", 60, 10, 240)
	d := time.Duration(window) * time.Second
	pts := s.Tel.Series(d, points)
	step := window / points
	if len(pts) > 1 {
		step = int(pts[1].T - pts[0].T)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window_sec":  window,
		"step_sec":    step,
		"points":      pts,
		"totals":      s.Tel.Window(d),
		"top_factors": nonNil(s.Tel.TopFactors(10)),
		"top_signals": nonNil(s.Tel.TopSignals(10)),
	})
}

func nonNil(c []telemetry.Counted) []telemetry.Counted {
	if c == nil {
		return []telemetry.Counted{}
	}
	return c
}

// handleEvents — последние рискованные решения из памяти (работает без Postgres).
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	decision := r.URL.Query().Get("decision")
	if decision != "" && decision != "review" && decision != "block" {
		s.badRequest(w, requestIDFrom(r.Context()), "invalid_decision")
		return
	}
	items := s.Tel.Recent(queryInt(r, "limit", 50, 1, 500), decision)
	if items == nil {
		items = []telemetry.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleModel(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Engine.ModelView())
}

// handleMLReport отдаёт отчёт об обучении ML-модели (кривые, распределения, разбор по типам). Отчёт меняется только
// при выкатке новой модели, поэтому кэшируется на короткое время: панель опрашивает раздел каждые несколько секунд.
func (s *Server) handleMLReport(w http.ResponseWriter, r *http.Request) {
	s.mlReport.mu.Lock()
	cached, fresh := s.mlReport.data, time.Since(s.mlReport.at) < mlReportTTL
	s.mlReport.mu.Unlock()
	if fresh && cached != nil {
		writeRaw(w, cached)
		return
	}
	data, err := s.Engine.MLReport(r.Context())
	if err != nil {
		s.writeMLError(w, err)
		return
	}
	s.mlReport.mu.Lock()
	s.mlReport.data, s.mlReport.at = data, time.Now()
	s.mlReport.mu.Unlock()
	writeRaw(w, data)
}

func (s *Server) handleMLService(w http.ResponseWriter, r *http.Request) {
	data, err := s.Engine.MLServiceStats(r.Context())
	if err != nil {
		s.writeMLError(w, err)
		return
	}
	writeRaw(w, data)
}

func (s *Server) writeMLError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, engine.ErrMLDisabled):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ML-сервис не подключён"})
	case errors.Is(err, mlclient.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "у текущей модели нет отчёта об обучении: переобучите модель (scripts/retrain.sh)"})
	default:
		s.Log.Warn("ml_report_failed", "err", err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "ML-сервис недоступен"})
	}
}

func writeRaw(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

const mlReportTTL = 30 * time.Second

type mlReportCache struct {
	mu   sync.Mutex
	data []byte
	at   time.Time
}

func (s *Server) handleFans(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"groups": s.Engine.FanGroups()})
}

// uiHandler отдаёт встроенную панель. Файлы небольшие и вкомпилированы в бинарь, поэтому кэш отключён
// (после деплоя пользователь сразу видит новую версию). Заголовки закрывают типовые векторы: внешние ресурсы
// запрещены (панель работает в закрытом контуре), встраивание во фреймы запрещено.
func uiHandler() http.Handler {
	files := http.FileServerFS(web.FS)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-cache")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		files.ServeHTTP(w, r)
	})
}

// mountUI регистрирует панель по /ui/, а корень перенаправляет на неё.
func (s *Server) mountUI(mux *http.ServeMux) {
	mux.Handle("GET /ui/", http.StripPrefix("/ui/", uiHandler()))
	mux.HandleFunc("GET /ui", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ui/", http.StatusMovedPermanently) })
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ui/", http.StatusFound) })
}

// uiFiles нужен тестам: список встроенных файлов.
func uiFiles() []string {
	var out []string
	_ = fs.WalkDir(web.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}
