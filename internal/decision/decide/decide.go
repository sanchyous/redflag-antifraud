// Package decide собирает итоговый вердикт allow / review / block.
//
// Автоблокировка — отдельное решение со своей ценой ошибки, поэтому block требует
// одновременно: высокую вероятность, не менее MinStrong независимых сильных сигналов и
// отсутствие защитного класса. Защитный слой стоит выше модели: экстренные службы — всегда
// allow, остальные защищённые классы — потолок review.
package decide

import (
	"github.com/sanchyous/redflag-antifraud/internal/detection/features"
	"github.com/sanchyous/redflag-antifraud/internal/detection/protect"
)

// Verdict — решение по вызову. Порядок значений — по возрастанию строгости.
type Verdict uint8

const (
	Allow Verdict = iota
	Review
	Block
)

func (v Verdict) String() string {
	switch v {
	case Review:
		return "review"
	case Block:
		return "block"
	}
	return "allow"
}

// Signals — битовая маска независимых сильных сигналов.
type Signals uint16

const (
	SigSpoof Signals = 1 << iota
	SigUnallocated
	SigFan
	SigBurst
	SigRegionSweep
	SigSimFarm
	SigRobot
)

var sigNames = [...]string{"spoof", "unallocated_caller", "fan", "burst", "region_sweep", "sim_farm", "robot"}

// Names возвращает имена взведённых сигналов.
func (s Signals) Names() []string {
	var out []string
	for i, n := range sigNames {
		if s&(1<<i) != 0 {
			out = append(out, n)
		}
	}
	return out
}

// Count — число взведённых сигналов.
func (s Signals) Count() int {
	c := 0
	for ; s != 0; s &= s - 1 {
		c++
	}
	return c
}

// Policy — пороги. Review и Block — вероятности из модели.
type Policy struct {
	Review, Block float32
	MinStrong     int     // сильных сигналов для block (по умолчанию 2)
	BurstCalls1h  float32 // вызовов в час для сигнала burst (по умолчанию 60)
	BurstShare    float32 // доля коротких/неотвеченных для burst (по умолчанию 0.7)
	SweepRegions  float32 // регионов за сутки для region_sweep (по умолчанию 20)
	FarmNumbers   float32 // «лишних» номеров абонента для sim_farm (по умолчанию 9)
	RobotIndex    float32 // индекс регулярности для robot (по умолчанию 0.9)
	RobotCalls1h  float32 // вызовов в час для robot (по умолчанию 20)
}

// Defaults подставляет значения по умолчанию в нулевые поля.
func (p Policy) Defaults() Policy {
	def := func(v *float32, d float32) {
		if *v <= 0 {
			*v = d
		}
	}
	if p.MinStrong <= 0 {
		p.MinStrong = 2
	}
	def(&p.BurstCalls1h, 60)
	def(&p.BurstShare, 0.7)
	def(&p.SweepRegions, 20)
	def(&p.FarmNumbers, 9)
	def(&p.RobotIndex, 0.9)
	def(&p.RobotCalls1h, 20)
	return p
}

// StrongSignals определяет независимые сильные сигналы по сырым значениям признаков.
func (p Policy) StrongSignals(v *features.Vector) Signals {
	r := &v.Raw
	var s Signals
	if r[features.Spoof] > 0 {
		s |= SigSpoof
	}
	if r[features.CallerUnallocated] > 0 {
		s |= SigUnallocated
	}
	if r[features.FanMember] > 0 {
		s |= SigFan
	}
	if r[features.OutCalls1h] >= p.BurstCalls1h &&
		(r[features.OutShortShare] >= p.BurstShare || r[features.OutUnansweredShare] >= p.BurstShare) {
		s |= SigBurst
	}
	if r[features.OutRegions24h] >= p.SweepRegions {
		s |= SigRegionSweep
	}
	if r[features.SubscriberNumbers] >= p.FarmNumbers {
		s |= SigSimFarm
	}
	if r[features.OutGapRobot] >= p.RobotIndex && r[features.OutCalls1h] >= p.RobotCalls1h {
		s |= SigRobot
	}
	return s
}

// HardSignals — сигналы-свидетельства: российский номер при иностранном входе (подмена) и номер из
// нераспределённого диапазона. Это не статистика, а прямое доказательство подмены CLI, поэтому они
// задают пол вердикта review независимо от модели. Значения битов — контракт с Python-сервисом
// (services/ml/training/evaluate.py: HARD_SIGNALS_MASK).
const HardSignals = SigSpoof | SigUnallocated

// Result — итог решения.
type Result struct {
	Verdict Verdict
	// BlockSuppressed — модель и сигналы требовали block, но защитный класс его запретил.
	BlockSuppressed bool
	// Floored — модель сказала allow, но сработало жёсткое правило: вердикт поднят до review.
	Floored bool
}

// Decide выносит вердикт. Инварианты (проверяются тестами):
//   - Emergency → всегда Allow, при любом score и сигналах;
//   - защищённый класс (NeverBlock) → никогда Block;
//   - Block только при score ≥ Block и не менее MinStrong сильных сигналов;
//   - жёсткий сигнал (HardSignals) → не ниже Review (модель не может его «отменить»); block из-за него
//     сам по себе не наступает.
func (p Policy) Decide(class protect.Class, score float32, sig Signals) Result {
	if class == protect.Emergency {
		return Result{Verdict: Allow}
	}
	v := Allow
	if score >= p.Review {
		v = Review
	}
	if score >= p.Block && sig.Count() >= p.MinStrong {
		v = Block
	}
	if v == Block && class.NeverBlock() {
		return Result{Verdict: Review, BlockSuppressed: true}
	}
	if v == Allow && sig&HardSignals != 0 {
		return Result{Verdict: Review, Floored: true}
	}
	return Result{Verdict: v}
}
