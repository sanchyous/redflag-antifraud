package scoring

import (
	"bytes"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/callrec"
	"github.com/sanchyous/redflag-antifraud/internal/enrich"
	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/window"
)

func typical() features.Vector {
	var v features.Vector
	res := enrich.Result{Event: callrec.Event{DurSec: 90, Flags: callrec.FlagAnswered}}
	features.Build(&features.Input{Res: &res, Win: window.Features{
		Out: window.NumFeatures{Calls1h: 1, Calls24h: 3, Peers1h: 1, Peers24h: 2},
	}}, &v)
	return v
}

func fraud() features.Vector {
	var v features.Vector
	res := enrich.Result{Spoof: true, ForeignIngress: true, Night: true,
		Event: callrec.Event{DurSec: 3, Flags: callrec.FlagAnswered | callrec.FlagSpoof | callrec.FlagForeignIngress}}
	features.Build(&features.Input{Res: &res, Win: window.Features{
		Out: window.NumFeatures{Calls1h: 300, Calls24h: 600, Peers1h: 300, Peers24h: 600, Regions24h: 40, RegionEntropy: 5,
			ShortShare: 0.95, UnansweredShare: 0.5, GapMeanSec: 12, GapCV: 0.05},
	}}, &v)
	return v
}

func TestPriorSeparatesTypicalFromFraud(t *testing.T) {
	m := Prior()
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	var ex Explanation
	tv := typical()
	m.Score(&tv, &ex)
	if ex.Score > 0.02 {
		t.Fatalf("typical subscriber scored %v", ex.Score)
	}
	fv := fraud()
	m.Score(&fv, &ex)
	if ex.Score < 0.99 {
		t.Fatalf("fraud pattern scored %v", ex.Score)
	}
}

func TestContributionsSumExactly(t *testing.T) {
	m := Prior()
	var ex Explanation
	for _, v := range []features.Vector{typical(), fraud()} {
		v := v
		m.Score(&v, &ex)
		// Σ всех вкладов + базовый logit = logit. Считаем все вклады заново.
		sum := float64(ex.BaseLogit)
		for i := 0; i < features.N; i++ {
			sum += float64(m.W[i]) * (float64(v.X[i]) - float64(m.Base[i]))
		}
		if math.Abs(sum-float64(ex.Logit)) > 1e-3 {
			t.Fatalf("decomposition mismatch: %v vs %v", sum, ex.Logit)
		}
		if math.Abs(float64(ex.Score)-Sigmoid(float64(ex.Logit))) > 1e-6 {
			t.Fatal("score must be sigmoid(logit)")
		}
	}
}

func TestTopContributionsOrderedAndCapped(t *testing.T) {
	m := Prior()
	var ex Explanation
	fv := fraud()
	m.Score(&fv, &ex)
	if ex.NPos != maxPos {
		t.Fatalf("NPos = %d, want %d", ex.NPos, maxPos)
	}
	for i := 1; i < ex.NPos; i++ {
		if ex.Pos[i-1].Contribution < ex.Pos[i].Contribution {
			t.Fatalf("Pos not sorted: %+v", ex.Pos[:ex.NPos])
		}
	}
	// самый большой вклад у сильного сигнала, а не у мелочи
	top := features.Names[ex.Pos[0].Feature]
	if top != "spoof" && top != "out_calls_1h" && top != "out_regions_24h" {
		t.Fatalf("unexpected top factor %s", top)
	}
	// длинный разговор — смягчающий фактор
	tv := typical()
	tv.X[features.CallDuration] = 8 // очень длинный
	tv.Raw[features.CallDuration] = 3000
	m.Score(&tv, &ex)
	if ex.NNeg == 0 || features.Names[ex.Neg[0].Feature] != "call_duration" {
		t.Fatalf("expected call_duration as mitigating factor: %+v", ex.Neg[:ex.NNeg])
	}
	for i := 1; i < ex.NNeg; i++ {
		if ex.Neg[i-1].Contribution > ex.Neg[i].Contribution {
			t.Fatal("Neg not sorted ascending")
		}
	}
}

func TestSigmoidStable(t *testing.T) {
	for _, x := range []float64{-1000, -50, 0, 50, 1000} {
		p := Sigmoid(x)
		if math.IsNaN(p) || p < 0 || p > 1 {
			t.Fatalf("Sigmoid(%v) = %v", x, p)
		}
	}
	if math.Abs(Logit(Sigmoid(2.5))-2.5) > 1e-9 {
		t.Fatal("Logit must invert Sigmoid")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	m := Prior()
	var buf bytes.Buffer
	if err := m.Write(&buf, map[string]float64{"auc": 0.97}); err != nil {
		t.Fatal(err)
	}
	m2, err := Load(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if *m2 != *m {
		t.Fatal("round trip changed the model")
	}
}

func TestLoadRejectsBadModels(t *testing.T) {
	var good bytes.Buffer
	if err := Prior().Write(&good, nil); err != nil {
		t.Fatal(err)
	}
	s := good.String()
	cases := map[string]string{
		"unknown feature": strings.Replace(s, `"spoof"`, `"spoof_x"`, 1),
		"duplicate":       strings.Replace(s, `"spoof"`, `"caller_invalid"`, 1),
		"bad thresholds":  strings.Replace(s, `"review": 0.15`, `"review": 0.95`, 1),
		"unknown field":   strings.Replace(s, `"version"`, `"vesion"`, 1),
		"not json":        "{",
	}
	for name, in := range cases {
		if _, err := Load(strings.NewReader(in)); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
	// потеря признака: вырезаем целиком запись spoof
	i := strings.Index(s, `{
      "name": "spoof",`)
	j := strings.Index(s[i:], "},") + i + 2
	if _, err := Load(strings.NewReader(s[:i] + s[j:])); err == nil {
		t.Fatal("model lacking a feature must be rejected")
	}
}

func TestValidateNaN(t *testing.T) {
	m := Prior()
	m.W[3] = float32(math.NaN())
	if m.Validate() == nil {
		t.Fatal("NaN weight must be rejected")
	}
	m = Prior()
	m.Bias = float32(math.Inf(1))
	if m.Validate() == nil {
		t.Fatal("Inf bias must be rejected")
	}
}

func BenchmarkScore(b *testing.B) {
	m := Prior()
	v := fraud()
	var ex Explanation
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.Score(&v, &ex)
	}
}

// Контракт с Python: модель стадии 1, обученная в ml-service/training/stage1.py, должна читаться ядром.
// Файл testdata/stage1_from_python.json — настоящий результат обучения (без метрик); при изменении формата
// на любой из сторон этот тест упадёт.
func TestLoadsStage1TrainedByPython(t *testing.T) {
	f, err := os.Open("testdata/stage1_from_python.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := Load(f)
	if err != nil {
		t.Fatalf("ядро не читает модель из Python: %v", err)
	}
	if !strings.HasPrefix(m.Version, "stage1-") || m.Review <= 0 || m.Block < m.Review {
		t.Fatalf("model header: %+v", m)
	}
	// смысловая проверка: у обученной модели монотонность знаков (рост признака не снижает риск)
	for i, name := range features.Names {
		w := m.W[i]
		if name == "call_duration" {
			if w > 0 {
				t.Fatalf("call_duration must not raise risk, w=%v", w)
			}
			continue
		}
		if w < 0 {
			t.Fatalf("%s has a negative weight %v: the explanation would contradict common sense", name, w)
		}
	}
	// и модель применима: подозрительный вектор оценивается выше обычного
	var ex Explanation
	fv, tv := fraud(), typical()
	m.Score(&fv, &ex)
	high := ex.Score
	m.Score(&tv, &ex)
	if !(high > ex.Score*10) {
		t.Fatalf("trained model must separate the patterns: fraud %v vs typical %v", high, ex.Score)
	}
}
