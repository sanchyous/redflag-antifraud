// Package mltrain — обучение и оценка модели: проигрывание потока вызовов через боевой
// движок (те же признаки, что в проде), логистическая регрессия (IRLS) с ограничениями
// знаков весов, подбор порогов по целевому FPR и метрики с разбивкой по типам абонентов.
package mltrain

import (
	"sync/atomic"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/decide"
	"github.com/sanchyous/redflag-antifraud/internal/engine"
	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/numplan"
	"github.com/sanchyous/redflag-antifraud/internal/protect"
	"github.com/sanchyous/redflag-antifraud/internal/scoring"
	"github.com/sanchyous/redflag-antifraud/internal/synth"
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
}

// Replay проигрывает вызовы по времени через новый движок и возвращает строки признаков.
// Часы движка ведутся по времени вызовов (детерминированно); индекс вееров пересчитывается
// каждые fanEvery модельного времени. Вызовы из samples изменяются (подставляются значения).
func Replay(plan *numplan.Plan, cls *protect.Classifier, samples []synth.Sample, fanEvery time.Duration) ([]Row, error) {
	var clock atomic.Int64
	if len(samples) > 0 {
		clock.Store(samples[0].Call.StartedAt.Unix())
	}
	eng, err := engine.New(engine.Config{
		Plan: plan, Classifier: cls, Now: func() time.Time { return time.Unix(clock.Load(), 0) },
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
		row := Row{Label: s.Fraud, Kind: s.Kind, Class: a.Class, Emergency: a.Emergency, Caller: s.Call.Caller, TS: ts}
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
