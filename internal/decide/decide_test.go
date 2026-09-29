package decide

import (
	"math/rand/v2"
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/protect"
)

func pol() Policy { return Policy{Review: 0.15, Block: 0.9}.Defaults() }

func TestDecideTable(t *testing.T) {
	two := SigSpoof | SigFan
	cases := []struct {
		name  string
		class protect.Class
		score float32
		sig   Signals
		want  Verdict
		supp  bool
	}{
		{"низкий риск", protect.None, 0.01, 0, Allow, false},
		{"граница review", protect.None, 0.15, 0, Review, false},
		{"чуть ниже review", protect.None, 0.1499, 0, Allow, false},
		{"высокий score, но сигналов мало → review", protect.None, 0.99, SigSpoof, Review, false},
		{"высокий score, ноль сигналов → review", protect.None, 0.99, 0, Review, false},
		{"два сигнала, но score ниже block → review", protect.None, 0.5, two, Review, false},
		{"score и два сигнала → block", protect.None, 0.9, two, Block, false},
		{"три сигнала → block", protect.None, 0.95, two | SigBurst, Block, false},
		{"allowlisted не блокируется", protect.Allowlisted, 0.99, two, Review, true},
		{"service short не блокируется", protect.ServiceShort, 0.99, two, Review, true},
		{"allowlisted с низким score", protect.Allowlisted, 0.01, 0, Allow, false},
		{"экстренная служба всегда allow", protect.Emergency, 0.999, two | SigBurst, Allow, false},
		{"подмена номера: модель молчит, но пол review", protect.None, 0.0001, SigSpoof, Review, false},
		{"нераспределённый CLI: пол review", protect.None, 0.0001, SigUnallocated, Review, false},
		{"объёмный сигнал не даёт пола", protect.None, 0.0001, SigBurst, Allow, false},
		{"экстренная важнее пола", protect.Emergency, 0.0001, SigSpoof, Allow, false},
		{"пол не превращается в block", protect.None, 0.5, SigSpoof, Review, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pol().Decide(tc.class, tc.score, tc.sig)
			if got.Verdict != tc.want || got.BlockSuppressed != tc.supp {
				t.Fatalf("got %+v, want %v suppressed=%v", got, tc.want, tc.supp)
			}
		})
	}
}

// Обязательный тест ответа на вопрос ТЗ: «что произойдёт, если система заблокирует вызов скорой».
// Перебираем весь диапазон score и все комбинации сигналов, для всех политик.
func TestEmergencyNeverBlocked(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 1))
	for i := 0; i < 200_000; i++ {
		p := Policy{Review: r.Float32()*0.5 + 0.01, Block: r.Float32()*0.5 + 0.5, MinStrong: 1 + r.IntN(3)}.Defaults()
		score := r.Float32()
		sig := Signals(r.Uint32() & 0x7f)
		res := p.Decide(protect.Emergency, score, sig)
		if res.Verdict != Allow {
			t.Fatalf("emergency call got %v (policy=%+v score=%v sig=%b)", res.Verdict, p, score, sig)
		}
	}
}

func TestHardSignalFloor(t *testing.T) {
	r := pol().Decide(protect.None, 0.0001, SigSpoof)
	if r.Verdict != Review || !r.Floored {
		t.Fatalf("floor: %+v", r)
	}
	// если модель и так отметила — пол не «сработал»
	if r := pol().Decide(protect.None, 0.5, SigSpoof); r.Floored {
		t.Fatalf("floor must not be reported when the model already flagged: %+v", r)
	}
	// защищённые классы тоже получают пол (review не блокирует), экстренные — нет
	if r := pol().Decide(protect.Allowlisted, 0.0001, SigUnallocated); r.Verdict != Review {
		t.Fatalf("allowlisted: %+v", r)
	}
	if r := pol().Decide(protect.Emergency, 0.0001, HardSignals); r.Verdict != Allow || r.Floored {
		t.Fatalf("emergency: %+v", r)
	}
}

// Значения битов сигналов — контракт с Python (HARD_SIGNALS_MASK). Менять порядок нельзя без правки там.
func TestSignalBitsAreStableContract(t *testing.T) {
	if SigSpoof != 1 || SigUnallocated != 2 || HardSignals != 3 {
		t.Fatalf("signal bits changed: spoof=%d unallocated=%d hard=%d", SigSpoof, SigUnallocated, HardSignals)
	}
}

func TestEmergencyNeverBlockedStillHoldsWithFloor(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 9))
	for i := 0; i < 100_000; i++ {
		res := pol().Decide(protect.Emergency, r.Float32(), Signals(r.Uint32()&0x7f)|HardSignals)
		if res.Verdict != Allow {
			t.Fatalf("emergency got %v", res.Verdict)
		}
	}
}

func TestProtectedClassesNeverBlocked(t *testing.T) {
	r := rand.New(rand.NewPCG(2, 2))
	for i := 0; i < 200_000; i++ {
		p := Policy{Review: r.Float32()*0.5 + 0.01, Block: r.Float32()*0.5 + 0.5, MinStrong: 1 + r.IntN(3)}.Defaults()
		class := protect.Class(1 + r.IntN(3))
		if res := p.Decide(class, r.Float32(), Signals(r.Uint32()&0x7f)); res.Verdict == Block {
			t.Fatalf("protected class %v got Block", class)
		}
	}
}

func TestBlockRequiresBothScoreAndSignals(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 3))
	for i := 0; i < 100_000; i++ {
		p := pol()
		score := r.Float32()
		sig := Signals(r.Uint32() & 0x7f)
		res := p.Decide(protect.None, score, sig)
		if res.Verdict == Block && (score < p.Block || sig.Count() < p.MinStrong) {
			t.Fatalf("block without justification: score=%v sig=%b", score, sig)
		}
	}
}

func TestStrongSignals(t *testing.T) {
	p := pol()
	var v features.Vector
	if p.StrongSignals(&v) != 0 {
		t.Fatal("empty vector has no signals")
	}
	v.Raw[features.Spoof] = 1
	v.Raw[features.CallerUnallocated] = 1
	v.Raw[features.FanMember] = 1
	v.Raw[features.OutCalls1h] = 100
	v.Raw[features.OutShortShare] = 0.8
	v.Raw[features.OutRegions24h] = 25
	v.Raw[features.SubscriberNumbers] = 9
	v.Raw[features.OutGapRobot] = 0.95
	got := p.StrongSignals(&v)
	want := SigSpoof | SigUnallocated | SigFan | SigBurst | SigRegionSweep | SigSimFarm | SigRobot
	if got != want || got.Count() != 7 {
		t.Fatalf("signals = %b, want %b", got, want)
	}
	if len(got.Names()) != 7 {
		t.Fatalf("names = %v", got.Names())
	}
	// burst требует и частоту, и аномальную долю
	var w features.Vector
	w.Raw[features.OutCalls1h] = 100
	if p.StrongSignals(&w)&SigBurst != 0 {
		t.Fatal("high rate alone is not burst (может быть легитимный колл-центр)")
	}
	w.Raw[features.OutCalls1h] = 59
	w.Raw[features.OutUnansweredShare] = 0.9
	if p.StrongSignals(&w)&SigBurst != 0 {
		t.Fatal("below rate threshold is not burst")
	}
}

func TestVerdictString(t *testing.T) {
	if Allow.String() != "allow" || Review.String() != "review" || Block.String() != "block" {
		t.Fatal("String mismatch")
	}
	var s Signals
	if s.Count() != 0 || len(s.Names()) != 0 {
		t.Fatal("empty signals")
	}
}
