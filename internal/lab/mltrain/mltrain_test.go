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
		{Label: true, Kind: synth.KindSpoofBurst, Class: protect.None, Signals: decide.SigSpoof | decide.SigFan, Caller: "+79161234567", TS: 1700000000},
		{Kind: synth.KindEmergency, Emergency: true, Class: protect.Emergency, Caller: "+79160000000", TS: 1700000001},
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
	if len(header) != 8+2*features.N || header[0] != "label" || header[7] != "s1" || header[8] != "r_out_calls_1h" || header[8+features.N] != "x_out_calls_1h" {
		t.Fatalf("header = %v", header)
	}
	row := strings.Split(lines[1], ",")
	if len(row) != len(header) || row[0] != "1" || row[1] != "spoof_burst" || row[3] != "5" || row[4] != "0" || row[8] != "340" {
		t.Fatalf("row = %v", row[:9])
	}
	if strings.Split(lines[2], ",")[4] != "1" {
		t.Fatal("emergency flag must be exported")
	}
	if len(ExportColumns()) != len(header) {
		t.Fatal("ExportColumns mismatch")
	}
}

func TestReplayDeterministic(t *testing.T) {
	plan := testPlan(t)
	run := func() []Row {
		ds := synth.Generate(synth.Config{Seed: 21, Plan: plan, Scale: 0.05, Days: 2})
		rows, err := Replay(plan, nil, nil, ds.Samples, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
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
