package engine

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decision/mlclient"
	"github.com/sanchyous/redflag-antifraud/internal/detection/features"
)

func TestInfoWithoutML(t *testing.T) {
	e, _ := newEngine(t, nil)
	in := e.Info()
	if in.ML.Enabled || in.ML.Active || in.ML.BreakerOpen {
		t.Fatalf("ML section: %+v", in.ML)
	}
	if in.Stage1.Version == "" || in.Policy.Review <= 0 || in.Policy.MinSignals < 1 {
		t.Fatalf("stage1/policy: %+v", in)
	}
	if !in.Numplan.Enabled || in.Numplan.Ranges == 0 || in.Numplan.Regions == 0 || in.Numplan.Version == "" {
		t.Fatalf("numplan: %+v", in.Numplan)
	}
	if in.TrackedNumbers != 0 || in.Protect.Allowlist != 0 {
		t.Fatalf("fresh engine: %+v", in)
	}
	e.Score(call("i-1", "+7 916 123-45-67", "+7 495 765-43-21", t0, 60))
	if e.Info().TrackedNumbers != 2 {
		t.Fatalf("tracked = %d, want 2 (caller and callee)", e.Info().TrackedNumbers)
	}
}

func TestInfoWithML(t *testing.T) {
	f := newFakeML(t)
	e, _ := newCascade(t, f, nil)
	in := e.Info()
	if !in.ML.Enabled || !in.ML.Active || in.ML.Version != "cb-test" || in.ML.Gate <= 0 || in.ML.BreakerOpen {
		t.Fatalf("ML section: %+v", in.ML)
	}
	// после серии сбоев breaker открывается и это видно в сводке
	f.status.Store(500)
	for i := 0; i < 5; i++ {
		e.Score(spoofCall(fmt.Sprint("b", i)))
	}
	if !e.Info().ML.BreakerOpen {
		t.Fatal("open breaker must be reflected in Info")
	}
}

func TestModelView(t *testing.T) {
	f := newFakeML(t)
	e, _ := newCascade(t, f, nil)
	v := e.ModelView()
	if len(v.Stage1.Features) != features.N || v.Stage1.Features[0].Name != features.Names[0] {
		t.Fatalf("features: %d", len(v.Stage1.Features))
	}
	if v.Stage1.Thresholds["review"] <= 0 || v.MinSignals < 1 {
		t.Fatalf("thresholds: %+v", v.Stage1.Thresholds)
	}
	if v.ML == nil || v.ML.Version != "cb-test" || len(v.ML.Features) != features.N {
		t.Fatalf("ML view: %+v", v.ML)
	}
	// без ML раздел пуст
	plain, _ := newEngine(t, nil)
	if plain.ModelView().ML != nil {
		t.Fatal("no ML → nil section")
	}
	_ = mlclient.Info{}
}

func TestFanGroupsAreMaskedAndSorted(t *testing.T) {
	e, clk := newEngine(t, nil)
	for i := 0; i < 40; i++ {
		for k := 0; k < 6; k++ {
			caller := fmt.Sprintf("+7 916 800-00-%02d", k)
			callee := fmt.Sprintf("+7 9%02d %03d-%02d-%02d", 10+k, i, k, i)
			e.Score(call(fmt.Sprintf("g-%d-%d", i, k), caller, callee, clk.Now(), 4))
		}
		clk.Advance(60)
	}
	e.RefreshFan()
	groups := e.FanGroups()
	if len(groups) != 1 || groups[0].Size != 6 || groups[0].Disjoint < 0.85 {
		t.Fatalf("groups = %+v", groups)
	}
	g := groups[0]
	if len(g.Members) != 6 || g.Label == "" || g.Label == "***" {
		t.Fatalf("group: %+v", g)
	}
	for _, m := range g.Members {
		if len(m.Number) < 8 || m.Number[:3] != "+7 " || len(m.Peers) == 0 {
			t.Fatalf("member: %+v", m)
		}
		for _, raw := range []string{"800-00-", "8000000"} {
			if contains(m.Number, raw) {
				t.Fatalf("raw digits leaked: %q", m.Number)
			}
		}
	}
	_ = time.Second
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestMaskKey(t *testing.T) {
	cases := map[uint64]string{
		79161234567:       "+7 916 ***-**-67",
		0:                 "***",
		(1 << 62) | 112:   "***", // короткий номер: ключ необратим
		(1 << 63) | 12345: "***", // маскированный номер
		12:                "***", // слишком короткое для номера
	}
	for k, want := range cases {
		if got := maskKey(k); got != want {
			t.Fatalf("maskKey(%d) = %q, want %q", k, got, want)
		}
	}
}

func TestEmptyFanGroups(t *testing.T) {
	e, _ := newEngine(t, nil)
	if g := e.FanGroups(); g == nil || len(g) != 0 {
		t.Fatalf("no fans → empty non-nil list, got %#v", g)
	}
	_ = context.Background()
}

func logged(t *testing.T) (*bytes.Buffer, func(*Config)) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &buf, func(c *Config) { c.Log = log }
}

func TestMLStateChangesAreLogged(t *testing.T) {
	buf, withLog := logged(t)
	f := newFakeML(t)
	e, _ := newCascade(t, f, withLog)
	if strings.Count(buf.String(), `"msg":"ml_stage_ready"`) != 1 || !strings.Contains(buf.String(), `"component":"engine"`) {
		t.Fatalf("activation must be logged once with the component: %s", buf)
	}
	// повторное чтение той же модели — не событие
	_ = e.RefreshML(context.Background())
	if strings.Count(buf.String(), "ml_stage_ready")+strings.Count(buf.String(), "ml_model_changed") != 1 {
		t.Fatalf("an unchanged model is not an event: %s", buf)
	}
	// новая версия модели
	inf := f.info.Load().(mlclient.Info)
	inf.Version = "cb-v2"
	f.info.Store(inf)
	_ = e.RefreshML(context.Background())
	if !strings.Contains(buf.String(), `"msg":"ml_model_changed"`) || !strings.Contains(buf.String(), `"to":"cb-v2"`) {
		t.Fatalf("version change: %s", buf)
	}
	// рассинхрон контракта → стадия отключена, событие уровня error
	inf.Features = inf.Features[:5]
	f.info.Store(inf)
	_ = e.RefreshML(context.Background())
	if !strings.Contains(buf.String(), `"msg":"ml_stage_disabled"`) || !strings.Contains(buf.String(), `"level":"ERROR"`) {
		t.Fatalf("disabling must be logged as an error: %s", buf)
	}
	// повторный сбой уже отключённой стадии не дублирует ошибку
	n := strings.Count(buf.String(), "ml_stage_disabled")
	_ = e.RefreshML(context.Background())
	if strings.Count(buf.String(), "ml_stage_disabled") != n {
		t.Fatal("the disable event is logged on the transition only")
	}
}

func TestFanRefreshLogLevels(t *testing.T) {
	buf, withLog := logged(t)
	e, clk := newEngine(t, withLog)
	e.RefreshFan()
	if strings.Contains(buf.String(), `"level":"INFO"`) {
		t.Fatalf("an empty, unchanged index must be debug: %s", buf)
	}
	for i := 0; i < 40; i++ {
		for k := 0; k < 6; k++ {
			e.Score(call(fmt.Sprintf("l-%d-%d", i, k), fmt.Sprintf("+7 916 800-00-%02d", k),
				fmt.Sprintf("+7 9%02d %03d-%02d-%02d", 10+k, i, k, i), clk.Now(), 4))
		}
		clk.Advance(60)
	}
	buf.Reset()
	e.RefreshFan()
	if !strings.Contains(buf.String(), `"level":"INFO"`) || !strings.Contains(buf.String(), `"groups":1`) || !strings.Contains(buf.String(), `"members":6`) {
		t.Fatalf("a change in the fans must be an info event: %s", buf)
	}
	buf.Reset()
	e.RefreshFan()
	if strings.Contains(buf.String(), `"level":"INFO"`) {
		t.Fatalf("the same fans again must be debug: %s", buf)
	}
}

func TestEngineWithoutLoggerDoesNotPanic(t *testing.T) {
	e, _ := newEngine(t, nil) // Log == nil
	e.RefreshFan()
	e.Score(spoofCall("nolog"))
}
