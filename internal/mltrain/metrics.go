package mltrain

import (
	"math"
	"sort"

	"github.com/sanchyous/redflag-antifraud/internal/decide"
	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/synth"
)

// Confusion — матрица ошибок для одного порога решения.
type Confusion struct {
	TP, FP, FN, TN int
}

// Precision, Recall, FPR — стандартные метрики; при нулевом знаменателе — 0.
func (c Confusion) Precision() float64 { return ratio(c.TP, c.TP+c.FP) }
func (c Confusion) Recall() float64    { return ratio(c.TP, c.TP+c.FN) }
func (c Confusion) FPR() float64       { return ratio(c.FP, c.FP+c.TN) }

// PrecisionAt — точность при заданной доле мошенничества в потоке (доля вызовов): точность
// зависит от распространённости, а recall и FPR — нет.
func (c Confusion) PrecisionAt(prevalence float64) float64 {
	r, f := c.Recall(), c.FPR()
	den := r*prevalence + f*(1-prevalence)
	if den == 0 {
		return 0
	}
	return r * prevalence / den
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// KindStat — исходы по типу абонента.
type KindStat struct {
	N          int
	Review     int // вердикт review или block
	Block      int
	Suppressed int // block отменён защитным классом
}

// Metrics — результат оценки модели и политики на наборе строк.
type Metrics struct {
	N, Legit, Fraud int
	AUC, PRAUC      float64
	Review          Confusion // порог «review или выше»
	Block           Confusion
	ByKind          map[synth.Kind]*KindStat

	// Уровень номеров-нарушителей: доля обнаруженных и сколько вызовов кампании прошло до реакции.
	FraudCallers        int
	CallersReviewed     int
	CallersBlocked      int
	MedianCallsToReview float64
	MedianCallsToBlock  float64

	Emergency struct{ N, Allowed, Blocked int }
}

// Score считает вероятность по строке.
func Score(m *scoring.Model, r *Row) float32 {
	z := float64(m.Bias)
	for i := 0; i < features.N; i++ {
		z += float64(m.W[i]) * float64(r.X[i])
	}
	return float32(scoring.Sigmoid(z))
}

// Verdict применяет политику к строке.
func Verdict(m *scoring.Model, pol decide.Policy, r *Row) (decide.Verdict, float32, bool) {
	if r.Emergency {
		return decide.Allow, 0, false
	}
	s := Score(m, r)
	res := pol.Decide(r.Class, s, r.Signals)
	return res.Verdict, s, res.BlockSuppressed
}

// Evaluate считает метрики. Экстренные вызовы учитываются отдельно и не входят в матрицы ошибок.
func Evaluate(rows []Row, m *scoring.Model, pol decide.Policy) *Metrics {
	mt := &Metrics{ByKind: map[synth.Kind]*KindStat{}}
	var sc []scored
	type callerStat struct {
		seen                       int
		firstReview, firstBlock    int
		reviewed, blocked, isFraud bool
	}
	callers := map[string]*callerStat{}

	for i := range rows {
		r := &rows[i]
		ks := mt.ByKind[r.Kind]
		if ks == nil {
			ks = &KindStat{}
			mt.ByKind[r.Kind] = ks
		}
		ks.N++
		v, s, supp := Verdict(m, pol, r)
		if r.Emergency {
			mt.Emergency.N++
			if v == decide.Allow {
				mt.Emergency.Allowed++
			}
			if v == decide.Block {
				mt.Emergency.Blocked++
			}
			continue
		}
		mt.N++
		if r.Label {
			mt.Fraud++
		} else {
			mt.Legit++
		}
		sc = append(sc, scored{s, r.Label})
		flagged, blocked := v >= decide.Review, v == decide.Block
		if flagged {
			ks.Review++
		}
		if blocked {
			ks.Block++
		}
		if supp {
			ks.Suppressed++
		}
		tally(&mt.Review, r.Label, flagged)
		tally(&mt.Block, r.Label, blocked)

		if r.Label {
			cs := callers[r.Caller]
			if cs == nil {
				cs = &callerStat{isFraud: true, firstReview: -1, firstBlock: -1}
				callers[r.Caller] = cs
			}
			if flagged && !cs.reviewed {
				cs.reviewed, cs.firstReview = true, cs.seen
			}
			if blocked && !cs.blocked {
				cs.blocked, cs.firstBlock = true, cs.seen
			}
			cs.seen++
		}
	}
	var toReview, toBlock []float64
	for _, cs := range callers {
		mt.FraudCallers++
		if cs.reviewed {
			mt.CallersReviewed++
			toReview = append(toReview, float64(cs.firstReview))
		}
		if cs.blocked {
			mt.CallersBlocked++
			toBlock = append(toBlock, float64(cs.firstBlock))
		}
	}
	mt.MedianCallsToReview = median(toReview)
	mt.MedianCallsToBlock = median(toBlock)
	mt.AUC, mt.PRAUC = rankMetrics(sc)
	return mt
}

func tally(c *Confusion, fraud, flagged bool) {
	switch {
	case fraud && flagged:
		c.TP++
	case fraud && !flagged:
		c.FN++
	case !fraud && flagged:
		c.FP++
	default:
		c.TN++
	}
}

func median(x []float64) float64 {
	if len(x) == 0 {
		return math.NaN()
	}
	sort.Float64s(x)
	n := len(x)
	if n%2 == 1 {
		return x[n/2]
	}
	return (x[n/2-1] + x[n/2]) / 2
}

type scored struct {
	s     float32
	fraud bool
}

// rankMetrics — ROC-AUC (Mann-Whitney со средними рангами для ничьих) и PR-AUC (средняя точность).
func rankMetrics(v []scored) (auc, prauc float64) {
	sort.Slice(v, func(i, j int) bool { return v[i].s < v[j].s })
	var nPos, nNeg float64
	for _, e := range v {
		if e.fraud {
			nPos++
		} else {
			nNeg++
		}
	}
	if nPos == 0 || nNeg == 0 {
		return math.NaN(), math.NaN()
	}
	var rankSum float64
	for i := 0; i < len(v); {
		j := i
		for j < len(v) && v[j].s == v[i].s {
			j++
		}
		avg := float64(i+j+1) / 2 // средний ранг (1-based) группы ничьих
		for k := i; k < j; k++ {
			if v[k].fraud {
				rankSum += avg
			}
		}
		i = j
	}
	auc = (rankSum - nPos*(nPos+1)/2) / (nPos * nNeg)

	// Средняя точность: идём от высоких score к низким.
	var tp, fp, ap, prevRecall float64
	for i := len(v) - 1; i >= 0; {
		j := i
		for j >= 0 && v[j].s == v[i].s {
			if v[j].fraud {
				tp++
			} else {
				fp++
			}
			j--
		}
		recall := tp / nPos
		ap += (recall - prevRecall) * (tp / (tp + fp))
		prevRecall = recall
		i = j
	}
	return auc, ap
}
