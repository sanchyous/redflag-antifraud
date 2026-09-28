package mltrain

import (
	"errors"
	"math"

	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/scoring"
)

const dim = features.N + 1 // признаки + смещение (последний индекс)

// FitOptions — параметры обучения.
type FitOptions struct {
	L2          float64 // L2-регуляризация весов признаков (не смещения); по умолчанию 5
	LegitWeight float64 // вес легитимных вызовов (>1 — ложное срабатывание дороже пропуска); по умолчанию 1
	MaxIter     int     // предел итераций Ньютона; по умолчанию 60
	// NonNegative — признаки, чей вес обязан быть неотрицательным (рост признака не может
	// снижать риск). Иначе объяснения противоречили бы здравому смыслу.
	NonNegative [features.N]bool
	// Prior — экспертные веса, к которым «тянет» регуляризация: штраф L2·‖w − prior‖²/2 вместо
	// L2·‖w‖²/2. Так признаки, избыточные на конкретных данных (например, spoof при идеально
	// разделяющей доле коротких вызовов), не обнуляются, а остаются около экспертной оценки;
	// данные отклоняют вес только там, где это убедительно. nil — тянет к нулю.
	Prior *[features.N]float64
}

// DefaultNonNegative: все признаки, кроме длительности разговора (длинный разговор — смягчающий фактор).
func DefaultNonNegative() [features.N]bool {
	var nn [features.N]bool
	for i := range nn {
		nn[i] = true
	}
	nn[features.CallDuration] = false
	return nn
}

// FitResult — обученные параметры.
type FitResult struct {
	Bias       float64
	W          [features.N]float64
	Iterations int
	Zeroed     []string // признаки, обнулённые ограничением знака
	Loss       float64
}

// Fit обучает взвешенную логистическую регрессию методом IRLS (Ньютона) с L2 и ограничениями
// знаков: признак с нарушенным знаком фиксируется в нуле, обучение повторяется.
func Fit(rows []Row, opt FitOptions) (*FitResult, error) {
	if opt.L2 <= 0 {
		opt.L2 = 5
	}
	if opt.LegitWeight <= 0 {
		opt.LegitWeight = 1
	}
	if opt.MaxIter <= 0 {
		opt.MaxIter = 60
	}
	var pos, neg int
	train := make([]*Row, 0, len(rows))
	for i := range rows {
		if rows[i].Emergency {
			continue // экстренные не проходят через модель
		}
		train = append(train, &rows[i])
		if rows[i].Label {
			pos++
		} else {
			neg++
		}
	}
	if pos == 0 || neg == 0 {
		return nil, errors.New("mltrain: need both fraud and legit rows")
	}
	var frozen [features.N]bool
	res := &FitResult{}
	for round := 0; round < features.N+1; round++ {
		beta, iters, loss := newton(train, opt, &frozen)
		res.Iterations += iters
		res.Loss = loss
		// Обнуляем по одному — самый «неправильный» признак: у почти коллинеарных признаков
		// (spoof / foreign_ingress / conn_international) знак одного из них случайно уходит в минус,
		// и одновременное обнуление всех нарушителей уничтожило бы полезные.
		worst, worstVal := -1, 0.0
		for i := 0; i < features.N; i++ {
			if opt.NonNegative[i] && !frozen[i] && beta[i] < worstVal {
				worst, worstVal = i, beta[i]
			}
		}
		if worst >= 0 {
			frozen[worst] = true
			continue
		}
		res.Bias = beta[features.N]
		for i := 0; i < features.N; i++ {
			res.W[i] = beta[i]
		}
		break
	}
	for i, f := range frozen {
		if f {
			res.Zeroed = append(res.Zeroed, features.Names[i])
		}
	}
	return res, nil
}

func rowWeight(r *Row, opt FitOptions) float64 {
	if r.Label {
		return 1
	}
	return opt.LegitWeight
}

// lossAt — регуляризованная взвешенная логистическая потеря в точке beta.
func lossAt(rows []*Row, opt FitOptions, frozen *[features.N]bool, beta *[dim]float64) float64 {
	var loss float64
	for _, r := range rows {
		z := beta[features.N]
		for i := 0; i < features.N; i++ {
			if !frozen[i] {
				z += beta[i] * float64(r.X[i])
			}
		}
		// log(1+e^z) - y*z, устойчиво
		var l float64
		if z > 0 {
			l = z + math.Log1p(math.Exp(-z))
		} else {
			l = math.Log1p(math.Exp(z))
		}
		if r.Label {
			l -= z
		}
		loss += rowWeight(r, opt) * l
	}
	for i := 0; i < features.N; i++ {
		if !frozen[i] {
			d := beta[i] - opt.anchor(i)
			loss += 0.5 * opt.L2 * d * d
		}
	}
	return loss
}

func (o FitOptions) anchor(i int) float64 {
	if o.Prior == nil {
		return 0
	}
	return o.Prior[i]
}

func newton(rows []*Row, opt FitOptions, frozen *[features.N]bool) (beta [dim]float64, iters int, loss float64) {
	// Стартовая точка: нули, смещение — logit доли положительных.
	var wp, wn float64
	for _, r := range rows {
		if r.Label {
			wp++
		} else {
			wn += opt.LegitWeight
		}
	}
	beta[features.N] = math.Log(wp / wn)
	if opt.Prior != nil {
		for i := 0; i < features.N; i++ {
			if !frozen[i] {
				beta[i] = opt.Prior[i]
			}
		}
	}

	free := make([]int, 0, dim)
	for i := 0; i < features.N; i++ {
		if !frozen[i] {
			free = append(free, i)
		}
	}
	free = append(free, features.N)
	k := len(free)
	const maxStepNorm = 4.0 // предел изменения одного параметра за итерацию

	loss = lossAt(rows, opt, frozen, &beta)
	for iters = 0; iters < opt.MaxIter; iters++ {
		grad := make([]float64, k)
		hess := make([]float64, k*k)
		for _, r := range rows {
			z := beta[features.N]
			for i := 0; i < features.N; i++ {
				if !frozen[i] {
					z += beta[i] * float64(r.X[i])
				}
			}
			p := scoring.Sigmoid(z)
			w := rowWeight(r, opt)
			y := 0.0
			if r.Label {
				y = 1
			}
			g := w * (p - y)
			h := w * p * (1 - p)
			for a := 0; a < k; a++ {
				xa := 1.0
				if fa := free[a]; fa < features.N {
					xa = float64(r.X[fa])
				}
				if xa == 0 {
					continue
				}
				grad[a] += g * xa
				for b := a; b < k; b++ {
					xb := 1.0
					if fb := free[b]; fb < features.N {
						xb = float64(r.X[fb])
					}
					hess[a*k+b] += h * xa * xb
				}
			}
		}
		for a := 0; a < k; a++ {
			for b := 0; b < a; b++ {
				hess[a*k+b] = hess[b*k+a]
			}
			if free[a] < features.N { // L2 на веса, не на смещение
				grad[a] += opt.L2 * (beta[free[a]] - opt.anchor(free[a]))
				hess[a*k+a] += opt.L2
			}
			hess[a*k+a] += 1e-9
		}
		step, err := solve(hess, grad, k)
		if err != nil {
			break
		}
		var maxAbs, dot float64
		for a := 0; a < k; a++ {
			maxAbs = math.Max(maxAbs, math.Abs(step[a]))
			dot += grad[a] * step[a]
		}
		scale := 1.0
		if maxAbs > maxStepNorm {
			scale = maxStepNorm / maxAbs
		}
		// Линейный поиск (backtracking, условие Армихо): шаг Ньютона на разделимых данных
		// может перескочить минимум.
		accepted := false
		for ls := 0; ls < 40; ls++ {
			cand := beta
			for a := 0; a < k; a++ {
				cand[free[a]] -= scale * step[a]
			}
			l1 := lossAt(rows, opt, frozen, &cand)
			if l1 <= loss-1e-4*scale*dot {
				rel := math.Abs(loss-l1) / math.Max(1, math.Abs(loss))
				beta, loss = cand, l1
				accepted = true
				if rel < 1e-10 {
					return beta, iters + 1, loss
				}
				break
			}
			scale /= 2
		}
		if !accepted || maxAbs*scale < 1e-7 {
			iters++
			break
		}
	}
	return beta, iters, loss
}

// solve решает A x = b методом Гаусса с выбором главного элемента (A — k×k по строкам).
func solve(A, b []float64, k int) ([]float64, error) {
	M := make([]float64, k*(k+1))
	for i := 0; i < k; i++ {
		copy(M[i*(k+1):i*(k+1)+k], A[i*k:i*k+k])
		M[i*(k+1)+k] = b[i]
	}
	w := k + 1
	for col := 0; col < k; col++ {
		piv := col
		for r := col + 1; r < k; r++ {
			if math.Abs(M[r*w+col]) > math.Abs(M[piv*w+col]) {
				piv = r
			}
		}
		if math.Abs(M[piv*w+col]) < 1e-14 {
			return nil, errors.New("mltrain: singular matrix")
		}
		if piv != col {
			for c := 0; c < w; c++ {
				M[col*w+c], M[piv*w+c] = M[piv*w+c], M[col*w+c]
			}
		}
		for r := col + 1; r < k; r++ {
			f := M[r*w+col] / M[col*w+col]
			if f == 0 {
				continue
			}
			for c := col; c < w; c++ {
				M[r*w+c] -= f * M[col*w+c]
			}
		}
	}
	x := make([]float64, k)
	for i := k - 1; i >= 0; i-- {
		s := M[i*w+k]
		for c := i + 1; c < k; c++ {
			s -= M[i*w+c] * x[c]
		}
		x[i] = s / M[i*w+i]
	}
	return x, nil
}
