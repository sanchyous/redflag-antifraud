// Package scoring — объяснимая аддитивная модель в лог-шансах (логистическая регрессия).
//
// logit = bias + Σ w_i·x_i. Вклад признака i относительно «эталонного» абонента:
// c_i = w_i·(x_i − base_i). Сумма вкладов плюс базовый logit равна итоговому logit ровно —
// это точное разложение (аналог SHAP для линейной модели), а не приближение: решение можно
// отладить и защитить перед регулятором.
package scoring

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/sanchyous/redflag-antifraud/internal/detection/features"
)

const (
	maxPos = 8
	maxNeg = 3
)

// Model — обученная (или априорная) модель.
type Model struct {
	Version string
	Bias    float32
	W       [features.N]float32
	Base    [features.N]float32 // значения преобразованных признаков «эталонного» абонента
	Review  float32             // порог вероятности для review
	Block   float32             // порог вероятности для block (вместе с независимыми сильными сигналами)
}

// Contribution — вклад одного признака.
type Contribution struct {
	Feature      uint8   // индекс в features.Names
	Raw          float32 // исходное значение признака
	Contribution float32 // вклад в лог-шансы, >0 повышает риск
}

// Explanation — результат скоринга с разложением.
type Explanation struct {
	Score     float32 // вероятность 0..1
	Logit     float32
	BaseLogit float32              // logit эталонного абонента
	Pos       [maxPos]Contribution // наибольшие вклады, повышающие риск, по убыванию
	NPos      int
	Neg       [maxNeg]Contribution // наибольшие вклады, снижающие риск, по возрастанию
	NNeg      int
}

// Score считает вероятность и разложение. Без аллокаций.
func (m *Model) Score(v *features.Vector, ex *Explanation) {
	*ex = Explanation{}
	logit := float64(m.Bias)
	base := float64(m.Bias)
	for i := 0; i < features.N; i++ {
		w := float64(m.W[i])
		logit += w * float64(v.X[i])
		base += w * float64(m.Base[i])
		c := float32(w * (float64(v.X[i]) - float64(m.Base[i])))
		switch {
		case c > 1e-6:
			insertPos(ex, Contribution{Feature: uint8(i), Raw: v.Raw[i], Contribution: c})
		case c < -1e-6:
			insertNeg(ex, Contribution{Feature: uint8(i), Raw: v.Raw[i], Contribution: c})
		}
	}
	ex.Logit = float32(logit)
	ex.BaseLogit = float32(base)
	ex.Score = float32(sigmoid(logit))
}

func insertPos(ex *Explanation, c Contribution) {
	i := ex.NPos
	if i == maxPos {
		if c.Contribution <= ex.Pos[maxPos-1].Contribution {
			return
		}
		i = maxPos - 1
	} else {
		ex.NPos++
	}
	for i > 0 && ex.Pos[i-1].Contribution < c.Contribution {
		ex.Pos[i] = ex.Pos[i-1]
		i--
	}
	ex.Pos[i] = c
}

func insertNeg(ex *Explanation, c Contribution) {
	i := ex.NNeg
	if i == maxNeg {
		if c.Contribution >= ex.Neg[maxNeg-1].Contribution {
			return
		}
		i = maxNeg - 1
	} else {
		ex.NNeg++
	}
	for i > 0 && ex.Neg[i-1].Contribution > c.Contribution {
		ex.Neg[i] = ex.Neg[i-1]
		i--
	}
	ex.Neg[i] = c
}

func sigmoid(x float64) float64 {
	if x >= 0 {
		return 1 / (1 + math.Exp(-x))
	}
	e := math.Exp(x)
	return e / (1 + e)
}

// Sigmoid — вероятность из logit (экспортирована для обучения и оценки).
func Sigmoid(x float64) float64 { return sigmoid(x) }

// Logit — обратная к Sigmoid.
func Logit(p float64) float64 { return math.Log(p / (1 - p)) }

// Validate проверяет корректность параметров.
func (m *Model) Validate() error {
	if !finite(m.Bias) {
		return errors.New("scoring: bias is not finite")
	}
	for i := 0; i < features.N; i++ {
		if !finite(m.W[i]) || !finite(m.Base[i]) {
			return fmt.Errorf("scoring: feature %s has non-finite parameters", features.Names[i])
		}
	}
	if !(m.Review > 0 && m.Review <= m.Block && m.Block <= 1) {
		return fmt.Errorf("scoring: thresholds must satisfy 0 < review (%v) <= block (%v) <= 1", m.Review, m.Block)
	}
	return nil
}

func finite(x float32) bool {
	f := float64(x)
	return !math.IsNaN(f) && !math.IsInf(f, 0)
}

type jsonFeature struct {
	Name string  `json:"name"`
	W    float32 `json:"w"`
	Base float32 `json:"base"`
}

type jsonModel struct {
	Version    string        `json:"version"`
	Bias       float32       `json:"bias"`
	Features   []jsonFeature `json:"features"`
	Thresholds struct {
		Review float32 `json:"review"`
		Block  float32 `json:"block"`
	} `json:"thresholds"`
	Metrics map[string]float64 `json:"metrics,omitempty"`
}

// Load читает модель из JSON и проверяет, что набор признаков совпадает с features.Names.
func Load(r io.Reader) (*Model, error) {
	var jm jsonModel
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&jm); err != nil {
		return nil, fmt.Errorf("scoring: decode model: %w", err)
	}
	idx := make(map[string]int, features.N)
	for i, n := range features.Names {
		idx[n] = i
	}
	m := &Model{Version: jm.Version, Bias: jm.Bias, Review: jm.Thresholds.Review, Block: jm.Thresholds.Block}
	seen := make([]bool, features.N)
	for _, f := range jm.Features {
		i, ok := idx[f.Name]
		if !ok {
			return nil, fmt.Errorf("scoring: unknown feature %q in model", f.Name)
		}
		if seen[i] {
			return nil, fmt.Errorf("scoring: duplicate feature %q in model", f.Name)
		}
		seen[i] = true
		m.W[i], m.Base[i] = f.W, f.Base
	}
	for i, ok := range seen {
		if !ok {
			return nil, fmt.Errorf("scoring: model lacks feature %q", features.Names[i])
		}
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// Write сериализует модель. metrics — необязательные метрики обучения.
func (m *Model) Write(w io.Writer, metrics map[string]float64) error {
	jm := jsonModel{Version: m.Version, Bias: m.Bias, Metrics: metrics}
	jm.Thresholds.Review, jm.Thresholds.Block = m.Review, m.Block
	for i, n := range features.Names {
		jm.Features = append(jm.Features, jsonFeature{Name: n, W: m.W[i], Base: m.Base[i]})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jm)
}
