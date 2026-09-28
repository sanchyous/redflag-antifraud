package mltrain

import (
	"bytes"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decide"
	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/numplan"
	"github.com/sanchyous/redflag-antifraud/internal/protect"
	"github.com/sanchyous/redflag-antifraud/internal/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/synth"
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

// toyRows: fraud ⇔ высокое значение признака Spoof/OutCalls1h с шумом.
func toyRows(n int, seed uint64) []Row {
	r := rand.New(rand.NewPCG(seed, 1))
	rows := make([]Row, n)
	for i := range rows {
		fraud := r.Float64() < 0.2
		row := Row{Label: fraud, Kind: synth.KindRegular, Caller: fmt.Sprint(i)}
		if fraud {
			row.Kind = synth.KindSpoofBurst
			row.X[features.Spoof] = 1
			row.X[features.OutCalls1h] = 3 + r.Float32()*2
		} else {
			row.X[features.OutCalls1h] = r.Float32() * 2
			if r.Float64() < 0.03 {
				row.X[features.Spoof] = 1 // редкий честный роумер
			}
		}
		row.X[features.CallDuration] = r.Float32() * 5
		rows[i] = row
	}
	return rows
}

func TestSolve(t *testing.T) {
	// 2x + y = 5; x + 3y = 10 → x = 1, y = 3
	x, err := solve([]float64{2, 1, 1, 3}, []float64{5, 10}, 2)
	if err != nil || math.Abs(x[0]-1) > 1e-9 || math.Abs(x[1]-3) > 1e-9 {
		t.Fatalf("x=%v err=%v", x, err)
	}
	if _, err := solve([]float64{1, 2, 2, 4}, []float64{1, 2}, 2); err == nil {
		t.Fatal("singular matrix must fail")
	}
}

func TestFitLearnsSignal(t *testing.T) {
	rows := toyRows(4000, 1)
	fit, err := Fit(rows, FitOptions{NonNegative: DefaultNonNegative()})
	if err != nil {
		t.Fatal(err)
	}
	if fit.W[features.OutCalls1h] <= 0.5 {
		t.Fatalf("OutCalls1h weight %v should be clearly positive", fit.W[features.OutCalls1h])
	}
	if fit.W[features.Spoof] < 0 {
		t.Fatalf("Spoof weight negative: %v", fit.W[features.Spoof])
	}
	m := BuildModel(fit, rows, BuildOptions{Version: "t"})
	mt := Evaluate(rows, m, decide.Policy{Review: 0.5, Block: 0.9}.Defaults())
	if mt.AUC < 0.97 {
		t.Fatalf("AUC = %v", mt.AUC)
	}
}

func TestFitNonNegativeConstraint(t *testing.T) {
	// Признак FanSize «спасает» мошенников наоборот: у мошенников он ниже → без ограничения вес был бы < 0.
	rows := toyRows(3000, 2)
	for i := range rows {
		if rows[i].Label {
			rows[i].X[features.FanSize] = 0
		} else {
			rows[i].X[features.FanSize] = 2
		}
	}
	free, _ := Fit(rows, FitOptions{}) // без ограничений
	if free.W[features.FanSize] >= 0 {
		t.Fatalf("test premise broken: unconstrained weight = %v", free.W[features.FanSize])
	}
	con, err := Fit(rows, FitOptions{NonNegative: DefaultNonNegative()})
	if err != nil {
		t.Fatal(err)
	}
	if con.W[features.FanSize] != 0 {
		t.Fatalf("constrained weight must be zero, got %v", con.W[features.FanSize])
	}
	found := false
	for _, n := range con.Zeroed {
		if n == "fan_size" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Zeroed = %v", con.Zeroed)
	}
	// длительность разрешено иметь отрицательный вес
	if DefaultNonNegative()[features.CallDuration] {
		t.Fatal("call_duration must be allowed to be negative")
	}
}

func TestFitNeedsBothClasses(t *testing.T) {
	rows := toyRows(100, 3)
	for i := range rows {
		rows[i].Label = false
	}
	if _, err := Fit(rows, FitOptions{}); err == nil {
		t.Fatal("single-class data must be rejected")
	}
}

func TestFitIgnoresEmergencyRows(t *testing.T) {
	rows := toyRows(500, 4)
	for i := 0; i < 50; i++ {
		rows = append(rows, Row{Emergency: true, Label: false, Kind: synth.KindEmergency})
	}
	if _, err := Fit(rows, FitOptions{NonNegative: DefaultNonNegative()}); err != nil {
		t.Fatal(err)
	}
}

func TestLegitWeightLowersScores(t *testing.T) {
	rows := toyRows(3000, 5)
	a, _ := Fit(rows, FitOptions{LegitWeight: 1, NonNegative: DefaultNonNegative()})
	b, _ := Fit(rows, FitOptions{LegitWeight: 5, NonNegative: DefaultNonNegative()})
	ma := BuildModel(a, rows, BuildOptions{})
	mb := BuildModel(b, rows, BuildOptions{})
	var sa, sb float64
	for i := range rows {
		if !rows[i].Label {
			sa += float64(Score(ma, &rows[i]))
			sb += float64(Score(mb, &rows[i]))
		}
	}
	if b.Bias >= a.Bias || sb >= sa {
		t.Fatalf("heavier legit weight must lower legit scores: bias %v→%v, sum %v→%v", a.Bias, b.Bias, sa, sb)
	}
}

func TestPrevalenceCalibration(t *testing.T) {
	rows := toyRows(3000, 6) // ~20% мошенничества
	fit, _ := Fit(rows, FitOptions{NonNegative: DefaultNonNegative()})
	train := BuildModel(fit, rows, BuildOptions{})
	prod := BuildModel(fit, rows, BuildOptions{Prevalence: 0.01})
	shift := float64(prod.Bias - train.Bias)
	want := scoring.Logit(0.01) - scoring.Logit(0.2)
	if math.Abs(shift-want) > 0.2 {
		t.Fatalf("bias shift %v, want ≈ %v", shift, want)
	}
	var trainMean, prodMean float64
	var n int
	for i := range rows {
		if !rows[i].Label {
			trainMean += float64(Score(train, &rows[i]))
			prodMean += float64(Score(prod, &rows[i]))
			n++
		}
	}
	if prodMean >= trainMean || prodMean/float64(n) > 0.01 {
		t.Fatalf("calibration to rarer fraud must lower legit scores: %v → %v", trainMean/float64(n), prodMean/float64(n))
	}
}

func TestRankMetrics(t *testing.T) {
	perfect := []scored{{0.1, false}, {0.2, false}, {0.8, true}, {0.9, true}}
	if auc, ap := rankMetrics(perfect); auc != 1 || ap != 1 {
		t.Fatalf("perfect: auc=%v ap=%v", auc, ap)
	}
	inverted := []scored{{0.1, true}, {0.2, true}, {0.8, false}, {0.9, false}}
	if auc, _ := rankMetrics(inverted); auc != 0 {
		t.Fatalf("inverted auc = %v", auc)
	}
	ties := []scored{{0.5, true}, {0.5, false}, {0.5, true}, {0.5, false}}
	if auc, _ := rankMetrics(ties); math.Abs(auc-0.5) > 1e-12 {
		t.Fatalf("all-ties auc = %v, want 0.5", auc)
	}
	if auc, _ := rankMetrics([]scored{{0.1, true}}); !math.IsNaN(auc) {
		t.Fatal("single class must give NaN")
	}
}

func TestConfusion(t *testing.T) {
	c := Confusion{TP: 80, FN: 20, FP: 10, TN: 990}
	if c.Recall() != 0.8 || math.Abs(c.FPR()-0.01) > 1e-12 || math.Abs(c.Precision()-80.0/90) > 1e-12 {
		t.Fatalf("%v %v %v", c.Recall(), c.FPR(), c.Precision())
	}
	// при 1% распространённости precision = 0.8*0.01 / (0.8*0.01 + 0.01*0.99)
	if got, want := c.PrecisionAt(0.01), 0.008/(0.008+0.0099); math.Abs(got-want) > 1e-9 {
		t.Fatalf("PrecisionAt = %v, want %v", got, want)
	}
	if (Confusion{}).Precision() != 0 || (Confusion{}).PrecisionAt(0.1) != 0 {
		t.Fatal("empty confusion must not divide by zero")
	}
}

func TestFitThresholdsRespectTargets(t *testing.T) {
	rows := toyRows(20000, 7)
	fit, _ := Fit(rows, FitOptions{NonNegative: DefaultNonNegative()})
	m := BuildModel(fit, rows, BuildOptions{Prevalence: 0.05})
	// у части легитимных «сильные сигналы», чтобы block-порог имел смысл
	for i := range rows {
		if !rows[i].Label && i%50 == 0 {
			rows[i].Signals = decide.SigSpoof | decide.SigFan
		}
		if rows[i].Label {
			rows[i].Signals = decide.SigSpoof | decide.SigFan
		}
	}
	tg := Targets{ReviewFPR: 0.01, BlockFPR: 0.001}
	m.Review, m.Block = FitThresholds(m, rows, 2, tg)
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	mt := Evaluate(rows, m, Policy(m, 2))
	if mt.Review.FPR() > tg.ReviewFPR+1e-9 {
		t.Fatalf("review FPR %.5f above target %.5f", mt.Review.FPR(), tg.ReviewFPR)
	}
	if mt.Block.FPR() > tg.BlockFPR+1e-9 {
		t.Fatalf("block FPR %.6f above target %.6f", mt.Block.FPR(), tg.BlockFPR)
	}
	if mt.Review.Recall() < 0.5 {
		t.Fatalf("thresholds are so strict that recall collapsed: %v", mt.Review.Recall())
	}
	if m.Block < m.Review {
		t.Fatal("block threshold below review")
	}
}

func TestQuantileAbove(t *testing.T) {
	v := []float64{0.1, 0.5, 0.2, 0.9, 0.3}
	if q := quantileAbove(append([]float64(nil), v...), 0); q <= 0.9 {
		t.Fatalf("allowed=0 → threshold must exceed the max, got %v", q)
	}
	q := quantileAbove(append([]float64(nil), v...), 2) // допускаем двоих над порогом: 0.9 и 0.5
	over := 0
	for _, x := range v {
		if x >= q {
			over++
		}
	}
	if over != 2 {
		t.Fatalf("threshold %v lets %d values through, want 2", q, over)
	}
	if quantileAbove(v, 5) != 0 || quantileAbove(nil, 0) != 0 {
		t.Fatal("no constraint when values do not exceed allowance")
	}
}

func TestEndToEndOnSynthetic(t *testing.T) {
	plan := testPlan(t)
	gen := func(seed uint64) ([]Row, *synth.Dataset) {
		ds := synth.Generate(synth.Config{Seed: seed, Plan: plan, Scale: 0.05, Days: 2})
		cls := protect.New()
		for _, a := range ds.Allowlist {
			cls.Add(a)
		}
		rows, err := Replay(plan, cls, ds.Samples, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return rows, ds
	}
	train, _ := gen(11)
	calib, _ := gen(12)
	test, _ := gen(13)

	fit, err := Fit(train, FitOptions{LegitWeight: 3, NonNegative: DefaultNonNegative()})
	if err != nil {
		t.Fatal(err)
	}
	m := BuildModel(fit, train, BuildOptions{Prevalence: 0.02, LegitWeight: 3, Version: "e2e"})
	m.Review, m.Block = FitThresholds(m, calib, 2, Targets{ReviewFPR: 0.01, BlockFPR: 0.0005})
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	pol := Policy(m, 2)
	mt := Evaluate(test, m, pol)

	if mt.AUC < 0.93 {
		t.Fatalf("AUC on unseen seed = %.4f", mt.AUC)
	}
	if mt.Emergency.N == 0 || mt.Emergency.Blocked != 0 || mt.Emergency.Allowed != mt.Emergency.N {
		t.Fatalf("emergency: %+v", mt.Emergency)
	}
	if mt.Review.FPR() > 0.03 {
		t.Fatalf("review FPR on unseen seed = %.4f", mt.Review.FPR())
	}
	// защищённые (allowlisted банки) не блокируются никогда
	for _, r := range test {
		if r.Class.NeverBlock() {
			v, _, _ := Verdict(m, pol, &r)
			if v == decide.Block {
				t.Fatal("protected row got Block")
			}
		}
	}
	if mt.Review.Recall() < 0.5 {
		t.Fatalf("review recall = %.3f", mt.Review.Recall())
	}
	if mt.FraudCallers == 0 || mt.CallersReviewed == 0 {
		t.Fatalf("caller-level metrics empty: %+v", mt)
	}

	var buf bytes.Buffer
	WriteReport(&buf, &ReportInfo{Title: "Тест", Date: "2026-01-01", Model: m, Fit: fit, Targets: Targets{ReviewFPR: 0.01, BlockFPR: 0.0005},
		Prevalence: 0.02, LegitWeight: 3, MinStrong: 2, TrainRows: len(train), CalibRows: len(calib), Test: mt, Notes: []string{"n"}})
	out := buf.String()
	for _, want := range []string{"# Тест", "Экстренные службы", "call_center", "spoof_burst", "Веса модели", "ROC-AUC"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report lacks %q", want)
		}
	}
	if !strings.Contains(Describe(m), "bias=") || !strings.HasPrefix(Stamp(time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)), "trained-20260102-0304") {
		t.Fatal("Describe/Stamp")
	}
}

func TestReplayDeterministic(t *testing.T) {
	plan := testPlan(t)
	run := func() []Row {
		ds := synth.Generate(synth.Config{Seed: 21, Plan: plan, Scale: 0.05, Days: 2})
		rows, err := Replay(plan, nil, ds.Samples, 10*time.Minute)
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
