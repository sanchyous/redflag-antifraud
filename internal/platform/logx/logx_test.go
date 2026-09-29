package logx

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func boolp(b bool) *bool { return &b }

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{"debug": slog.LevelDebug, "INFO": slog.LevelInfo, " warn ": slog.LevelWarn,
		"warning": slog.LevelWarn, "error": slog.LevelError, "": slog.LevelInfo, "шум": slog.LevelInfo}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Fatalf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestJSONFormatHasServiceVersionAndRequestID(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Format: "json", Service: "decision-api", Version: "1.2.3", Out: &buf})
	ctx := WithRequestID(context.Background(), "req-42")
	l.InfoContext(ctx, "decision", "call_id", "c-1", "score", 0.15)
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not json: %q", buf.String())
	}
	if rec["msg"] != "decision" || rec["service"] != "decision-api" || rec["version"] != "1.2.3" ||
		rec["request_id"] != "req-42" || rec["call_id"] != "c-1" || rec["score"] != 0.15 {
		t.Fatalf("record = %v", rec)
	}
	if RequestID(context.Background()) != "" || RequestID(ctx) != "req-42" {
		t.Fatal("RequestID accessor")
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Format: "json", Level: "warn", Out: &buf})
	l.Info("hidden")
	l.Warn("shown")
	if strings.Contains(buf.String(), "hidden") || !strings.Contains(buf.String(), "shown") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestPrettyLayout(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Format: "pretty", Out: &buf, Color: boolp(false)})
	l = Component(l, "api")
	l.Info("decision", "call_id", "c-1", "reason", "два слова", "n", 3, "ok", true, "score", 0.123456789, "d", 1500*time.Millisecond)
	line := strings.TrimSpace(buf.String())
	if !strings.Contains(line, "INFO ") || !strings.Contains(line, "api        decision") {
		t.Fatalf("layout: %q", line)
	}
	for _, want := range []string{"call_id=c-1", `reason="два слова"`, "n=3", "ok=true", "score=0.123457", "d=1.5s"} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in %q", want, line)
		}
	}
	if strings.Contains(line, "\x1b[") {
		t.Fatal("no color escape codes when color is off")
	}
	if len(line) < 12 || line[2] != ':' || line[5] != ':' || line[8] != '.' {
		t.Fatalf("time prefix: %q", line)
	}
}

func TestPrettyColorAndLevels(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Format: "pretty", Level: "debug", Out: &buf, Color: boolp(true)})
	l.Debug("d")
	l.Warn("w")
	l.Error("e")
	out := buf.String()
	if strings.Count(out, "\n") != 3 || !strings.Contains(out, "\x1b[31m") || !strings.Contains(out, "\x1b[33m") {
		t.Fatalf("color output: %q", out)
	}
	for _, lvl := range []string{"DEBUG", "WARN ", "ERROR"} {
		if !strings.Contains(out, lvl) {
			t.Fatalf("level %q missing", lvl)
		}
	}
}

func TestPrettyGroupsAndWith(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Format: "pretty", Out: &buf, Color: boolp(false)}).With("region", "ru").WithGroup("call").With("id", "c-9")
	l.Info("evt", "k", "v")
	line := buf.String()
	if !strings.Contains(line, "region=ru") || !strings.Contains(line, "call.id=c-9") || !strings.Contains(line, "call.k=v") {
		t.Fatalf("groups: %q", line)
	}
}

func TestPrettyIsConcurrencySafe(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Format: "pretty", Out: &buf, Color: boolp(false)})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				l.Info("evt", "g", g, "i", i)
			}
		}(g)
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1600 {
		t.Fatalf("lines = %d, records must never interleave", len(lines))
	}
	for _, ln := range lines {
		if !strings.Contains(ln, "evt g=") {
			t.Fatalf("corrupted line: %q", ln)
		}
	}
}

func TestDefaultFormatIsJSONForNonTerminal(t *testing.T) {
	var buf bytes.Buffer
	New(Config{Out: &buf}).Info("x")
	if !strings.HasPrefix(buf.String(), "{") {
		t.Fatalf("non-terminal default must be json: %q", buf.String())
	}
}

func TestComponentAndDiscard(t *testing.T) {
	var buf bytes.Buffer
	l := Component(New(Config{Format: "json", Out: &buf}), "engine")
	l.Info("x")
	if !strings.Contains(buf.String(), `"component":"engine"`) {
		t.Fatalf("component: %q", buf.String())
	}
	Component(nil, "x").Info("must not panic")
	Discard().Error("nothing")
}

func TestRateLimitDropsBurstAndReports(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(RateLimit(slog.NewJSONHandler(&buf, nil), 5))
	base := time.Unix(1_000_000, 0)
	emit := func(at time.Time, msg string, lvl slog.Level) {
		r := slog.NewRecord(at, lvl, msg, 0)
		_ = l.Handler().Handle(context.Background(), r)
	}
	for i := 0; i < 50; i++ {
		emit(base, "decision", slog.LevelInfo)
	}
	if n := strings.Count(buf.String(), `"msg":"decision"`); n != 5 {
		t.Fatalf("first second must let exactly 5 through, got %d", n)
	}
	emit(base.Add(time.Second), "decision", slog.LevelInfo) // новая секунда → сводка + пропуск
	out := buf.String()
	if !strings.Contains(out, `"msg":"log_dropped"`) || !strings.Contains(out, `"dropped":45`) {
		t.Fatalf("summary of dropped records expected: %s", out)
	}
	// другое сообщение считается отдельно
	before := buf.Len()
	emit(base.Add(time.Second), "another", slog.LevelInfo)
	if buf.Len() == before {
		t.Fatal("limits are per message")
	}
}

func TestRateLimitNeverDropsWarnings(t *testing.T) {
	var buf bytes.Buffer
	h := RateLimit(slog.NewJSONHandler(&buf, nil), 1)
	base := time.Unix(2_000_000, 0)
	for i := 0; i < 20; i++ {
		_ = h.Handle(context.Background(), slog.NewRecord(base, slog.LevelError, "boom", 0))
		_ = h.Handle(context.Background(), slog.NewRecord(base, slog.LevelWarn, "careful", 0))
	}
	if strings.Count(buf.String(), "boom") != 20 || strings.Count(buf.String(), "careful") != 20 {
		t.Fatal("warnings and errors must never be rate limited")
	}
}

func TestRateLimitWithAttrsSharesState(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(RateLimit(slog.NewJSONHandler(&buf, nil), 2))
	child := l.With("component", "api")
	for i := 0; i < 10; i++ {
		l.Info("evt")
		child.Info("evt")
	}
	if n := strings.Count(buf.String(), `"msg":"evt"`); n != 2 {
		t.Fatalf("parent and child share one budget per message, got %d", n)
	}
	if !l.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("Enabled must delegate")
	}
	_ = l.WithGroup("g")
}

func BenchmarkJSONInfo(b *testing.B) {
	var buf bytes.Buffer
	l := New(Config{Format: "json", Out: &buf})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if buf.Len() > 1<<20 {
			buf.Reset()
		}
		l.Info("decision", "call_id", "c-1", "decision", "review", "score", 0.15)
	}
}
