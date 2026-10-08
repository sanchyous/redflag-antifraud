package mltrain

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decision/decide"
	"github.com/sanchyous/redflag-antifraud/internal/detection/features"
	"github.com/sanchyous/redflag-antifraud/internal/detection/protect"
	"github.com/sanchyous/redflag-antifraud/internal/lab/synth"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/callrec"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/numplan"
)

func testPlan(t testing.TB) *numplan.Plan {
	var sb strings.Builder
	sb.WriteString("АВС/ DEF;От;До;Емкость;Оператор;Регион;Территория ГАР;ИНН\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&sb, "9%02d;0000000;9999999;10000000;ПАО \"МТС\";-;Регион %02d;7740000076\n", i, i)
	}
	b := numplan.NewBuilder()
	if err := b.AddCSV(strings.NewReader(sb.String())); err != nil {
		t.Fatal(err)
	}
	p, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExportCSV(t *testing.T) {
	rows := []Row{
		{Label: true, Kind: synth.KindSpoofBurst, Class: protect.None, Signals: decide.SigSpoof | decide.SigFan, Caller: "+79161234567", Callee: "+79169999999", TS: 1700000000},
		{Kind: synth.KindEmergency, Emergency: true, Class: protect.Emergency, Caller: "+79160000000", Callee: "103", TS: 1700000001},
	}
	rows[0].Raw[features.OutCalls1h], rows[0].X[features.OutCalls1h] = 340, 5.83
	var buf bytes.Buffer
	if err := ExportCSV(&buf, rows); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d", len(lines))
	}
	header := strings.Split(lines[0], ",")
	if len(header) != 9+2*features.N || header[0] != "label" || header[6] != "callee" || header[8] != "s1" || header[9] != "r_out_calls_1h" || header[9+features.N] != "x_out_calls_1h" {
		t.Fatalf("header = %v", header)
	}
	row := strings.Split(lines[1], ",")
	if len(row) != len(header) || row[0] != "1" || row[1] != "spoof_burst" || row[3] != "5" || row[4] != "0" || row[6] != "+79169999999" || row[9] != "340" {
		t.Fatalf("row = %v", row[:10])
	}
	if strings.Split(lines[2], ",")[4] != "1" {
		t.Fatal("emergency flag must be exported")
	}
	if len(ExportColumns()) != len(header) {
		t.Fatal("ExportColumns mismatch")
	}
}

// TestReplaySkipsInvalidRowsInsteadOfAborting — внешние выгрузки (cmd/export -input) могут содержать
// единичный мусор (здесь — номер с невыделенным кодом страны); одна плохая строка не должна ронять
// обучение на остальных тысячах.
func TestReplaySkipsInvalidRowsInsteadOfAborting(t *testing.T) {
	plan := testPlan(t)
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	good := func(id string, dt time.Duration) synth.Sample {
		return synth.Sample{Call: callrec.Call{CallID: id, Caller: "+79001234567", Callee: "+79161234567",
			StartedAt: t0.Add(dt), DurationSec: 5}}
	}
	samples := []synth.Sample{
		good("ok-1", 0),
		{Call: callrec.Call{CallID: "bad", Caller: "+79001234567", Callee: "+99999999999", StartedAt: t0.Add(time.Second)}}, // код страны 999 не существует
		good("ok-2", 2*time.Second),
	}
	rows, skipped, err := Replay(plan, nil, nil, samples, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (bad row dropped, good ones kept)", len(rows))
	}
	for _, r := range rows {
		if r.Caller != "+79001234567" {
			t.Fatalf("unexpected row survived: %+v", r)
		}
	}
}

// TestReplayDetectsNewGraphPatterns — проверяет не форму данных, а то, что получаемые от synth
// вызовы реально срабатывают через боевой движок: для каждого из четырёх новых типов (клон SIM,
// цепочка переадресации, SIM-box, карусель) соответствующий жёсткий сигнал должен загореться у
// заметной доли вызовов этого типа. Без этого теста можно было бы сгенерировать правдоподобно
// выглядящие вызовы, которые тем не менее не долетают до порогов детекторов (как уже было с
// mltrain.Replay, который до этого коммита пересчитывал только веер, не остальные три индекса).
func TestReplayDetectsNewGraphPatterns(t *testing.T) {
	plan := testPlan(t)
	ds := synth.Generate(synth.Config{Seed: 5, Plan: plan, Scale: 0.1, Days: 3})
	rows, skipped, err := Replay(plan, nil, nil, ds.Samples, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Fatalf("synthetic data must never be skipped by the engine, got %d", skipped)
	}
	hit := map[synth.Kind]int{}
	total := map[synth.Kind]int{}
	want := map[synth.Kind]decide.Signals{
		synth.KindImsiClone:    decide.SigSimClone,
		synth.KindForwardChain: decide.SigChain,
		synth.KindSimBox:       decide.SigSimBox,
		synth.KindCarousel:     decide.SigCarousel,
	}
	for _, r := range rows {
		sig, tracked := want[r.Kind]
		if !tracked {
			continue
		}
		total[r.Kind]++
		if r.Signals&sig != 0 {
			hit[r.Kind]++
		}
	}
	for kind, sig := range want {
		if total[kind] == 0 {
			t.Fatalf("no samples of kind %s generated", kind)
		}
		share := float64(hit[kind]) / float64(total[kind])
		if share < 0.5 {
			t.Fatalf("%s: signal %s fired on only %.0f%% of %d samples (%d hit) — generator likely doesn't clear the detector's threshold",
				kind, sig.Names(), share*100, total[kind], hit[kind])
		}
	}
}

func TestReplayDeterministic(t *testing.T) {
	plan := testPlan(t)
	run := func() []Row {
		ds := synth.Generate(synth.Config{Seed: 21, Plan: plan, Scale: 0.05, Days: 2})
		rows, skipped, err := Replay(plan, nil, nil, ds.Samples, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if skipped != 0 {
			t.Fatalf("synthetic data must never be skipped by the engine, got %d", skipped)
		}
		return rows
	}
	a, b := run(), run()
	if len(a) != len(b) || len(a) == 0 {
		t.Fatal("sizes")
	}
	for i := range a {
		if a[i].X != b[i].X || a[i].Label != b[i].Label {
			t.Fatalf("row %d differs between identical runs", i)
		}
	}
}
