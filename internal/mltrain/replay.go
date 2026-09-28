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
	"github.com/sanchyous/redflag-antifraud/internal/synth"
)

// Row — признаки одного вызова с меткой.
type Row struct {
	X         [features.N]float32
	Label     bool // мошеннический
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
		row := Row{Label: s.Fraud, Kind: s.Kind, Class: a.Class, Emergency: a.Emergency, Caller: s.Call.Caller}
		if !a.Emergency {
			row.X = a.Vec.X
			row.Signals = pol.StrongSignals(&a.Vec)
		}
		rows = append(rows, row)
	}
	return rows, nil
}
