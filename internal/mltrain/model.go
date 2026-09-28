package mltrain

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decide"
	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/scoring"
)

// BuildOptions — параметры сборки модели из результата обучения.
type BuildOptions struct {
	// Prevalence — ожидаемая доля мошеннических вызовов в боевом потоке. Смещение подбирается так,
	// чтобы score был откалиброван под неё (пороги при этом выбираются по FPR и от неё не зависят).
	Prevalence  float64
	LegitWeight float64 // вес легитимных при обучении (нужен для пересчёта эффективной доли)
	Version     string
}

// BuildModel собирает модель: веса из FitResult, базовый профиль — среднее признаков легитимных
// вызовов, смещение — с поправкой на распространённость.
func BuildModel(fit *FitResult, rows []Row, opt BuildOptions) *scoring.Model {
	m := &scoring.Model{Version: opt.Version}
	var base [features.N]float64
	var n float64
	var wp, wn float64
	lw := opt.LegitWeight
	if lw <= 0 {
		lw = 1
	}
	for i := range rows {
		r := &rows[i]
		if r.Emergency {
			continue
		}
		if r.Label {
			wp++
			continue
		}
		wn += lw
		n++
		for k := 0; k < features.N; k++ {
			base[k] += float64(r.X[k])
		}
	}
	for k := 0; k < features.N; k++ {
		if n > 0 {
			m.Base[k] = float32(base[k] / n)
		}
		m.W[k] = float32(fit.W[k])
	}
	bias := fit.Bias
	if opt.Prevalence > 0 && opt.Prevalence < 1 && wp > 0 {
		trainPrior := wp / (wp + wn)
		bias += scoring.Logit(opt.Prevalence) - scoring.Logit(trainPrior)
	}
	m.Bias = float32(bias)
	m.Review, m.Block = 0.5, 1
	return m
}

// Targets — целевые доли ложных срабатываний на легитимном потоке.
type Targets struct {
	ReviewFPR float64 // доля легитимных вызовов, уходящих в review или выше (по умолчанию 0.01)
	BlockFPR  float64 // доля легитимных вызовов, попадающих под block (по умолчанию 0.0001)
}

// FitThresholds подбирает пороги review и block по целевому FPR на калибровочном наборе.
// Block считается по полной политике: учитываются сильные сигналы и защитные классы.
// Пороги строго «больше k-го по величине легитимного score», поэтому доля превышений не больше цели.
func FitThresholds(m *scoring.Model, rows []Row, minStrong int, t Targets) (review, block float32) {
	if t.ReviewFPR <= 0 {
		t.ReviewFPR = 0.01
	}
	if t.BlockFPR <= 0 {
		t.BlockFPR = 0.0001
	}
	var legitScores, blockable []float64
	legit := 0
	for i := range rows {
		r := &rows[i]
		if r.Emergency || r.Label {
			continue
		}
		legit++
		s := float64(Score(m, r))
		legitScores = append(legitScores, s)
		if r.Signals.Count() >= minStrong && !r.Class.NeverBlock() {
			blockable = append(blockable, s)
		}
	}
	review = float32(quantileAbove(legitScores, int(math.Floor(t.ReviewFPR*float64(legit)))))
	if review < 0.001 {
		review = 0.001
	}
	block = float32(quantileAbove(blockable, int(math.Floor(t.BlockFPR*float64(legit)))))
	if block < review {
		block = review
	}
	if block < 0.5 {
		block = 0.5 // block по определению — высокая уверенность
	}
	if block > 1 {
		block = 1
	}
	return review, block
}

// quantileAbove возвращает наименьший порог, при котором не более allowed значений его достигают:
// число элементов >= порога не превышает allowed. Ноль — ограничений нет (значений не больше allowed).
func quantileAbove(vals []float64, allowed int) float64 {
	if len(vals) <= allowed {
		return 0
	}
	sort.Float64s(vals)
	v := vals[len(vals)-1-allowed] // (allowed+1)-й по величине
	// Порог хранится и сравнивается как float32: шаг вверх делаем в float32, иначе округление
	// вернуло бы порог на само значение и ничьи на границе прошли бы его.
	return float64(math.Nextafter32(float32(v), 2))
}

// Policy собирает политику из модели и параметров.
func Policy(m *scoring.Model, minStrong int) decide.Policy {
	return decide.Policy{Review: m.Review, Block: m.Block, MinStrong: minStrong}.Defaults()
}

// Describe — краткое текстовое описание обученной модели (веса по убыванию модуля).
func Describe(m *scoring.Model) string {
	type kv struct {
		name string
		w    float32
	}
	var l []kv
	for i, n := range features.Names {
		l = append(l, kv{n, m.W[i]})
	}
	sort.Slice(l, func(i, j int) bool { return math.Abs(float64(l[i].w)) > math.Abs(float64(l[j].w)) })
	s := fmt.Sprintf("bias=%.3f review=%.4f block=%.4f", m.Bias, m.Review, m.Block)
	for _, e := range l {
		s += fmt.Sprintf("\n  %-22s %+.3f", e.name, e.w)
	}
	return s
}

// Stamp — версия модели по времени обучения.
func Stamp(now time.Time) string { return "trained-" + now.UTC().Format("20060102-1504") }

// PriorWeights возвращает веса экспертной модели для якорной регуляризации (FitOptions.Prior).
func PriorWeights() *[features.N]float64 {
	pm := scoring.Prior()
	var w [features.N]float64
	for i := range w {
		w[i] = float64(pm.W[i])
	}
	return &w
}
