package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decision/engine"
	"github.com/sanchyous/redflag-antifraud/internal/decision/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/platform/logx"
	"github.com/sanchyous/redflag-antifraud/web"
)

// spoofBody — вызов с подменой номера (даёт review по жёсткому правилу).
func spoofBody(id string) string {
	return fmt.Sprintf(`{"call_id":%q,"caller":"+7 495 ***-**-12","callee":"+7 916 ***-**-83","duration_sec":6,"src_country":"DE"}`, id)
}

func okBody(id string) string {
	return fmt.Sprintf(`{"call_id":%q,"caller":"+7 916 123-45-67","callee":"+7 495 765-43-21","duration_sec":200}`, id)
}

func TestStatusShape(t *testing.T) {
	s := newServer(t, func(s *Server) { s.Version = "9.9.9" })
	h := s.Routes()
	do(t, h, "POST", "/v1/calls/score", spoofBody("s1"))
	do(t, h, "POST", "/v1/calls/score", okBody("s2"))
	do(t, h, "POST", "/v1/calls/score", `{"callee":"103"}`)

	rr := do(t, h, "GET", "/v1/status", "")
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	var st statusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Service.Version != "9.9.9" || st.Service.Name != "decision-api" || st.Service.CPUs < 1 || st.Service.Goroutine < 1 || st.Service.HeapMB <= 0 {
		t.Fatalf("service = %+v", st.Service)
	}
	if st.Engine.Stage1.Version == "" || !st.Engine.Numplan.Enabled || st.Engine.Numplan.Ranges == 0 {
		t.Fatalf("engine = %+v", st.Engine)
	}
	if st.Totals.Allow != 2 || st.Totals.Review != 1 || st.Totals.Emergency != 1 || st.Totals.Linear != 3 {
		t.Fatalf("totals = %+v", st.Totals)
	}
	if st.Config.Auth || !st.Config.FailOpen || st.Store.Enabled || st.Journal.Enabled {
		t.Fatalf("config/store/journal = %+v %+v %+v", st.Config, st.Store, st.Journal)
	}
	if strings.Contains(rr.Body.String(), "secret") {
		t.Fatal("status must not leak secrets")
	}
}

func TestStatusReflectsAuthConfig(t *testing.T) {
	s := newServer(t, func(s *Server) { s.APIKey = "k" })
	h := s.Routes()
	if rr := do(t, h, "GET", "/v1/status", ""); rr.Code != 401 {
		t.Fatalf("status must be protected: %d", rr.Code)
	}
	rr := do(t, h, "GET", "/v1/status", "", "X-API-Key", "k")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"auth":true`) {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	for _, p := range []string{"/v1/stats", "/v1/events", "/v1/model", "/v1/graph/fans"} {
		if rr := do(t, h, "GET", p, ""); rr.Code != 401 {
			t.Fatalf("%s must be protected, got %d", p, rr.Code)
		}
	}
}

func TestStatsSeriesAndTotals(t *testing.T) {
	h := newServer(t, nil).Routes()
	for i := 0; i < 5; i++ {
		do(t, h, "POST", "/v1/calls/score", spoofBody(fmt.Sprint("sp", i)))
	}
	for i := 0; i < 20; i++ {
		do(t, h, "POST", "/v1/calls/score", okBody(fmt.Sprint("ok", i)))
	}
	rr := do(t, h, "GET", "/v1/stats?window=300&points=30", "")
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
	var out struct {
		WindowSec int `json:"window_sec"`
		StepSec   int `json:"step_sec"`
		Points    []struct {
			Allow, Review, Block, Total uint64
		} `json:"points"`
		Totals struct {
			Total, Allow, Review uint64
			P50US                float64 `json:"p50_us"`
			P99US                float64 `json:"p99_us"`
		} `json:"totals"`
		TopFactors []struct {
			Name  string
			Count uint64
		} `json:"top_factors"`
		TopSignals []struct{ Name string } `json:"top_signals"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.WindowSec != 300 || out.StepSec != 10 || len(out.Points) != 30 {
		t.Fatalf("window=%d step=%d points=%d", out.WindowSec, out.StepSec, len(out.Points))
	}
	var sum uint64
	for _, p := range out.Points {
		sum += p.Total
	}
	if sum != 25 || out.Totals.Total != 25 || out.Totals.Review != 5 || out.Totals.Allow != 20 {
		t.Fatalf("sum=%d totals=%+v", sum, out.Totals)
	}
	if len(out.TopFactors) == 0 || len(out.TopSignals) == 0 || out.TopSignals[0].Name != "spoof" {
		t.Fatalf("top factors/signals: %+v %+v", out.TopFactors, out.TopSignals)
	}
}

func TestStatsParametersAreClamped(t *testing.T) {
	h := newServer(t, nil).Routes()
	cases := map[string][2]int{
		"":                          {900, 60},
		"?window=1&points=1":        {60, 10},
		"?window=99999999&points=9": {86400, 10},
		"?window=abc&points=xyz":    {900, 60},
		"?window=600&points=100000": {600, 240},
	}
	for q, want := range cases {
		rr := do(t, h, "GET", "/v1/stats"+q, "")
		var out struct {
			WindowSec int              `json:"window_sec"`
			Points    []map[string]any `json:"points"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || rr.Code != 200 {
			t.Fatalf("%q: %d %v", q, rr.Code, err)
		}
		if out.WindowSec != want[0] || len(out.Points) != want[1] {
			t.Fatalf("%q → window=%d points=%d, want %v", q, out.WindowSec, len(out.Points), want)
		}
	}
}

func TestEventsFilterAndValidation(t *testing.T) {
	h := newServer(t, nil).Routes()
	if rr := do(t, h, "GET", "/v1/events", ""); rr.Code != 200 || !strings.Contains(rr.Body.String(), `"items":[]`) {
		t.Fatalf("empty list must be [], got %d %s", rr.Code, rr.Body)
	}
	do(t, h, "POST", "/v1/calls/score", spoofBody("e1"))
	do(t, h, "POST", "/v1/calls/score", spoofBody("e2"))
	do(t, h, "POST", "/v1/calls/score", okBody("e3")) // allow в события не попадает
	rr := do(t, h, "GET", "/v1/events?limit=10", "")
	var out struct {
		Items []struct {
			CallID                   string `json:"call_id"`
			Decision, Caller, Callee string
			Reasons                  []struct{ Factor, Effect string }
			Signals                  []string
		}
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || len(out.Items) != 2 {
		t.Fatalf("events: %v %s", err, rr.Body)
	}
	if out.Items[0].CallID != "e2" || out.Items[0].Decision != "review" || out.Items[0].Caller != "+7 495 ***-**-12" {
		t.Fatalf("newest first with masked numbers: %+v", out.Items[0])
	}
	if len(out.Items[0].Reasons) == 0 || out.Items[0].Reasons[0].Factor != "spoof" || out.Items[0].Signals[0] != "spoof" {
		t.Fatalf("the top reason must be the spoofing: %+v", out.Items[0].Reasons)
	}
	if rr := do(t, h, "GET", "/v1/events?decision=block", ""); !strings.Contains(rr.Body.String(), `"items":[]`) {
		t.Fatalf("no blocks yet: %s", rr.Body)
	}
	if rr := do(t, h, "GET", "/v1/events?decision=allow", ""); rr.Code != 400 || !strings.Contains(rr.Body.String(), "invalid_decision") {
		t.Fatalf("allow is not an event: %d %s", rr.Code, rr.Body)
	}
}

func TestModelAndFansEndpoints(t *testing.T) {
	h := newServer(t, nil).Routes()
	rr := do(t, h, "GET", "/v1/model", "")
	var m struct {
		Stage1 struct {
			Version  string
			Features []struct {
				Name string
				W    float64
			}
		}
		MinSignals int `json:"min_signals"`
		ML         any `json:"ml"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil || rr.Code != 200 {
		t.Fatalf("%d %v", rr.Code, err)
	}
	if len(m.Stage1.Features) != 26 || m.Stage1.Version == "" || m.MinSignals < 1 || m.ML != nil {
		t.Fatalf("model view: %+v", m)
	}
	rr = do(t, h, "GET", "/v1/graph/fans", "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"groups":[]`) {
		t.Fatalf("no fans → empty list: %d %s", rr.Code, rr.Body)
	}
}

func TestValidationErrorsAreCounted(t *testing.T) {
	s := newServer(t, nil)
	h := s.Routes()
	do(t, h, "POST", "/v1/calls/score", `{`)
	do(t, h, "POST", "/v1/calls/score", `{"call_id":"x","callee":"мусор"}`)
	if got := s.Tel.Totals().Errors; got != 2 {
		t.Fatalf("errors = %d, want 2", got)
	}
}

// ---- панель ----

func TestUIServedWithSecurityHeaders(t *testing.T) {
	h := newServer(t, nil).Routes()
	rr := do(t, h, "GET", "/ui/", "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "RedFlag") {
		t.Fatalf("%d %.80s", rr.Code, rr.Body)
	}
	for k, want := range map[string]string{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-cache"} {
		if rr.Header().Get(k) != want {
			t.Fatalf("header %s = %q", k, rr.Header().Get(k))
		}
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "http://") || strings.Contains(csp, "https://") {
		t.Fatalf("CSP must forbid external resources: %q", csp)
	}
	js := do(t, h, "GET", "/ui/js/app.js", "")
	if js.Code != 200 || !strings.Contains(js.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("js: %d %q", js.Code, js.Header().Get("Content-Type"))
	}
	if css := do(t, h, "GET", "/ui/css/app.css", ""); css.Code != 200 || !strings.Contains(css.Header().Get("Content-Type"), "css") {
		t.Fatalf("css: %d %q", css.Code, css.Header().Get("Content-Type"))
	}
	if nf := do(t, h, "GET", "/ui/js/nope.js", ""); nf.Code != 404 {
		t.Fatalf("missing asset: %d", nf.Code)
	}
}

func TestUIRedirectsAndStaysOpenWithAuth(t *testing.T) {
	h := newServer(t, func(s *Server) { s.APIKey = "k" }).Routes()
	if rr := do(t, h, "GET", "/", ""); rr.Code != http.StatusFound || rr.Header().Get("Location") != "/ui/" {
		t.Fatalf("root redirect: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if rr := do(t, h, "GET", "/ui", ""); rr.Code != http.StatusMovedPermanently {
		t.Fatalf("/ui redirect: %d", rr.Code)
	}
	// страница открыта (ключ вводится в интерфейсе), данные — за ключом
	if rr := do(t, h, "GET", "/ui/", ""); rr.Code != 200 {
		t.Fatalf("ui must be reachable without a key: %d", rr.Code)
	}
}

var (
	reImport = regexp.MustCompile(`(?m)^import\s+(?:\{([^}]*)\}|\*\s+as\s+(\w+))\s+from\s+'(\.[^']+)'`)
	reExport = func(name string) *regexp.Regexp {
		return regexp.MustCompile(`(?m)^export\s+(?:async\s+)?(?:function|const|let|class)\s+` + regexp.QuoteMeta(name) + `\b`)
	}
)

// Node.js в проекте нет, поэтому сломанный импорт (опечатка в пути или в имени) превратился бы в «белый экран».
// Тест статически проверяет: все относительные импорты указывают на существующие файлы и на реально экспортируемые имена.
func TestUIModulesImportOnlyExistingExports(t *testing.T) {
	files := uiFiles()
	if len(files) < 10 {
		t.Fatalf("embedded UI looks incomplete: %v", files)
	}
	count := 0
	for _, f := range files {
		if !strings.HasSuffix(f, ".js") {
			continue
		}
		src, err := fs.ReadFile(web.FS, f)
		if err != nil {
			t.Fatal(err)
		}
		dir := f[:strings.LastIndex(f, "/")]
		for _, m := range reImport.FindAllStringSubmatch(string(src), -1) {
			count++
			target := path(dir, m[3])
			body, err := fs.ReadFile(web.FS, target)
			if err != nil {
				t.Fatalf("%s imports %q which does not exist (%s)", f, m[3], target)
			}
			if m[1] == "" {
				continue // import * as ns
			}
			for _, name := range strings.Split(m[1], ",") {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				if i := strings.Index(name, " as "); i >= 0 {
					name = strings.TrimSpace(name[:i])
				}
				if !reExport(name).Match(body) {
					t.Fatalf("%s imports {%s} from %s, but it is not exported there", f, name, target)
				}
			}
		}
	}
	if count < 20 {
		t.Fatalf("suspiciously few imports checked: %d", count)
	}
}

// path разрешает относительный путь модуля (./x.js, ../y.js) внутри встроенной ФС.
func path(dir, rel string) string {
	parts := strings.Split(dir, "/")
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case ".", "":
		case "..":
			parts = parts[:len(parts)-1]
		default:
			parts = append(parts, seg)
		}
	}
	return strings.Join(parts, "/")
}

// Все данные, которые запрашивает панель, обязаны существовать в API: сверяем пути из api.js с маршрутами.
func TestUIApiPathsExist(t *testing.T) {
	src, err := fs.ReadFile(web.FS, "js/api.js")
	if err != nil {
		t.Fatal(err)
	}
	h := newServer(t, nil).Routes()
	for _, m := range regexp.MustCompile("'(/v1/[a-z/]+)").FindAllStringSubmatch(string(src), -1) {
		rr := do(t, h, "GET", m[1], "")
		if rr.Code == http.StatusNotFound || rr.Code == http.StatusMethodNotAllowed {
			// /v1/calls/score — POST; остальные — GET
			if m[1] != "/v1/calls/score" {
				t.Fatalf("UI requests %s, but the API has no such route (%d)", m[1], rr.Code)
			}
		}
	}
}

// ---- логирование решений ----

func loggedServer(t *testing.T, mode, level string) (*Server, *bytes.Buffer) {
	var buf bytes.Buffer
	s := newServer(t, func(s *Server) {
		s.Log = logx.New(logx.Config{Format: "json", Level: level, Out: &buf})
		s.LogDecisions = mode
	})
	return s, &buf
}

func TestDecisionLoggedAsStructuredEvent(t *testing.T) {
	s, buf := loggedServer(t, "", "info")
	h := s.Routes()
	do(t, h, "POST", "/v1/calls/score", spoofBody("log-1"), "X-Request-Id", "req-7")
	var rec map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(ln), &r) == nil && r["msg"] == "decision" {
			rec = r
		}
	}
	if rec == nil {
		t.Fatalf("decision event not logged: %s", buf)
	}
	if rec["decision"] != "review" || rec["call_id"] != "log-1" || rec["caller"] != "+7 495 ***-**-12" ||
		rec["request_id"] != "req-7" || rec["level"] != "INFO" || rec["top_reason"] == "" {
		t.Fatalf("event fields: %v", rec)
	}
	if sig, _ := rec["signals"].([]any); len(sig) != 1 || sig[0] != "spoof" {
		t.Fatalf("signals: %v", rec["signals"])
	}
	if strings.Contains(buf.String(), "123-45-67") {
		t.Fatal("raw numbers must never reach the log")
	}
}

func TestDecisionLoggingModes(t *testing.T) {
	count := func(mode, level string) (allow, flagged int) {
		s, buf := loggedServer(t, mode, level)
		h := s.Routes()
		do(t, h, "POST", "/v1/calls/score", okBody("m-ok"))
		do(t, h, "POST", "/v1/calls/score", spoofBody("m-sp"))
		for _, ln := range strings.Split(buf.String(), "\n") {
			if !strings.Contains(ln, `"msg":"decision"`) {
				continue
			}
			if strings.Contains(ln, `"decision":"allow"`) {
				allow++
			} else {
				flagged++
			}
		}
		return
	}
	if a, f := count("", "debug"); a != 0 || f != 1 {
		t.Fatalf("default: only flagged decisions are logged, got allow=%d flagged=%d", a, f)
	}
	if a, f := count("all", "debug"); a != 1 || f != 1 {
		t.Fatalf("all at debug level: allow=%d flagged=%d", a, f)
	}
	if a, f := count("all", "info"); a != 0 || f != 1 {
		t.Fatalf("allow is a debug event: %d %d", a, f)
	}
	if a, f := count("off", "debug"); a != 0 || f != 0 {
		t.Fatalf("off: %d %d", a, f)
	}
}

func TestAccessLogHasSingleRequestID(t *testing.T) {
	s, buf := loggedServer(t, "off", "info")
	do(t, s.Routes(), "GET", "/v1/status", "", "X-Request-Id", "abc")
	line := ""
	for _, ln := range strings.Split(buf.String(), "\n") {
		if strings.Contains(ln, `"msg":"http_request"`) {
			line = ln
		}
	}
	if line == "" {
		t.Fatalf("access log missing: %s", buf)
	}
	if strings.Count(line, `"request_id"`) != 1 || !strings.Contains(line, `"request_id":"abc"`) {
		t.Fatalf("access log must carry request_id exactly once: %s", line)
	}
	_ = slog.LevelInfo
	_ = httptest.NewRecorder
}

// Жёсткий пол: модель со строгими порогами «молчит», но подмена номера — прямое свидетельство.
func TestRuleFloorVisibleInEventsAndLog(t *testing.T) {
	strict := scoring.Prior()
	strict.Review, strict.Block = 0.9999, 1
	eng, err := engine.New(engine.Config{Plan: testPlan(t), Model: strict, Now: func() time.Time { return time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	s := &Server{Engine: eng, Log: logx.New(logx.Config{Format: "json", Out: &buf}), FailOpen: true}
	h := s.Routes()
	do(t, h, "POST", "/v1/calls/score", spoofBody("floor-1"))

	var ev struct {
		Items []struct {
			RuleFloor bool `json:"rule_floor"`
			Reasons   []struct{ Factor, Text string }
		}
	}
	if err := json.Unmarshal(do(t, h, "GET", "/v1/events", "").Body.Bytes(), &ev); err != nil || len(ev.Items) != 1 {
		t.Fatalf("events: %v", err)
	}
	if !ev.Items[0].RuleFloor || ev.Items[0].Reasons[0].Factor != "rule_spoof" || ev.Items[0].Reasons[0].Text == "" {
		t.Fatalf("the rule must be flagged and named first: %+v", ev.Items[0])
	}
	if !strings.Contains(buf.String(), `"summary":"Вызов +7 495`) {
		t.Fatalf("the log event must carry the summary: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"rule_floor":true`) {
		t.Fatalf("the log event must say the floor fired: %s", buf.String())
	}
	var st statusResponse
	_ = json.Unmarshal(do(t, h, "GET", "/v1/status", "").Body.Bytes(), &st)
	if st.Totals.RuleFloors != 1 {
		t.Fatalf("rule floors total = %d", st.Totals.RuleFloors)
	}
}

// benchBodies заранее готовит тела запросов: в горячем цикле бенчмарка нет ни форматирования, ни генерации.
func benchBodies(n int) []string {
	out := make([]string, n)
	for i := range out {
		if i%20 == 0 { // 5% подозрительных
			out[i] = fmt.Sprintf(`{"call_id":"b%d","caller":"+7 495 %03d-%02d-%02d","callee":"+7 916 %03d-%02d-%02d","duration_sec":4,"src_country":"DE","conn_type":"international"}`,
				i, i%1000, i%100, (i/7)%100, (i/3)%1000, i%100, i%97)
		} else {
			out[i] = fmt.Sprintf(`{"call_id":"b%d","caller":"+7 916 %03d-%02d-%02d","callee":"+7 495 %03d-%02d-%02d","duration_sec":%d}`,
				i, i%1000, i%100, (i/7)%100, (i/3)%1000, i%100, i%97, 20+i%300)
		}
	}
	return out
}

// BenchmarkHandleScore измеряет весь HTTP-обработчик (разбор запроса, скоринг, кодирование ответа, телеметрия) без сети.
func BenchmarkHandleScore(b *testing.B) {
	h := newServer(b, nil).Routes()
	bodies := benchBodies(1 << 15)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		rec := httptest.NewRecorder()
		for pb.Next() {
			i++
			req := httptest.NewRequest("POST", "/v1/calls/score", strings.NewReader(bodies[i&(1<<15-1)]))
			rec.Body.Reset()
			h.ServeHTTP(rec, req)
		}
	})
}
