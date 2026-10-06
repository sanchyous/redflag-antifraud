// Package mltrain — подготовка данных для обучения: проигрывание потока вызовов через боевой
// движок (те же признаки, что в проде) и экспорт датасета для ML-сервиса (Python). Само обучение,
// подбор порогов и оценка живут в services/ml/training (CatBoost, scikit-learn).
package mltrain

import (
	"sync/atomic"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decision/decide"
	"github.com/sanchyous/redflag-antifraud/internal/decision/engine"
	"github.com/sanchyous/redflag-antifraud/internal/decision/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/detection/features"
	"github.com/sanchyous/redflag-antifraud/internal/detection/protect"
	"github.com/sanchyous/redflag-antifraud/internal/lab/synth"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/numplan"
)

// Row — признаки одного вызова с меткой.
type Row struct {
	X         [features.N]float32 // вход линейной модели (log1p для счётчиков)
	Raw       [features.N]float32 // значения в исходных единицах (для деревьев и объяснений)
	TS        int64
	Score1    float32 // оценка стадии 1 (боевая линейная модель) — для подбора «серой зоны» каскада
	Label     bool    // мошеннический
	Kind      synth.Kind
	Class     protect.Class
	Emergency bool
	Signals   decide.Signals
	Caller    string
	Callee    string // получатель вызова: нужен для построения графа связей (ADR-0018)
}

// Replay проигрывает вызовы по времени через новый движок и возвращает строки признаков.
// Часы движка ведутся по времени вызовов (детерминированно); индекс вееров пересчитывается
// каждые fanEvery модельного времени. Вызовы из samples изменяются (подставляются значения).
//
// model — линейная модель стадии 1, по которой считаются Score1 и порог «сильных» сигналов; nil — экспертная.
func Replay(plan *numplan.Plan, cls *protect.Classifier, model *scoring.Model, samples []synth.Sample, fanEvery time.Duration) ([]Row, error) {
	var clock atomic.Int64
	if len(samples) > 0 {
		clock.Store(samples[0].Call.StartedAt.Unix())
	}
	eng, err := engine.New(engine.Config{
		Plan: plan, Classifier: cls, Model: model, Now: func() time.Time { return time.Unix(clock.Load(), 0) },
	})
	if err != nil {
		return nil, err
	}
	pol := eng.Policy()
	stage1 := eng.Model()
	rows := make([]Row, 0, len(samples))
	var lastFan int64
	for i := range samples {
		s := &samples[i]
		ts := s.Call.StartedAt.Unix()
		clock.Store(ts)
		if fanEvery > 0 && ts-lastFan >= int64(fanEvery.Seconds()) {
			eng.RefreshFan()
			lastFan = ts
		}
		a, err := eng.Analyze(&s.Call)
		if err != nil {
			return nil, err
		}
		row := Row{Label: s.Fraud, Kind: s.Kind, Class: a.Class, Emergency: a.Emergency, Caller: s.Call.Caller, Callee: s.Call.Callee, TS: ts}
		if !a.Emergency {
			row.X, row.Raw = a.Vec.X, a.Vec.Raw
			row.Signals = pol.StrongSignals(&a.Vec)
			var ex scoring.Explanation
			stage1.Score(&a.Vec, &ex)
			row.Score1 = ex.Score
		}
		rows = append(rows, row)
	}
	return rows, nil
}
