package synth

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/numplan"
	"github.com/sanchyous/redflag-antifraud/internal/phone"
)

func testPlan(t testing.TB) *numplan.Plan {
	var sb strings.Builder
	sb.WriteString("АВС/ DEF;От;До;Емкость;Оператор;Регион;Территория ГАР;ИНН\n")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&sb, "9%02d;0000000;9999999;10000000;ПАО \"МТС\";-;Регион %02d;7740000076\n", i, i)
	}
	for i := 0; i < 5; i++ {
		fmt.Fprintf(&sb, "4%02d;0000000;9999999;10000000;ПАО МГТС;г. Город %d;Город %d;7710016640\n", 10+i, i, i)
	}
	b := numplan.NewBuilder()
	if err := b.AddCSV(strings.NewReader(sb.String())); err != nil {
		t.Fatal(err)
	}
	p, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func small(seed uint64, p *numplan.Plan) Config {
	return Config{Seed: seed, Plan: p, Scale: 0.05, Days: 2}
}

func TestDeterministic(t *testing.T) {
	p := testPlan(t)
	a := Generate(small(7, p))
	b := Generate(small(7, p))
	if len(a.Samples) != len(b.Samples) || len(a.Samples) == 0 {
		t.Fatalf("sizes %d / %d", len(a.Samples), len(b.Samples))
	}
	for i := range a.Samples {
		x, y := a.Samples[i], b.Samples[i]
		if x.Call.CallID != y.Call.CallID || x.Call.Caller != y.Call.Caller || x.Call.Callee != y.Call.Callee ||
			!x.Call.StartedAt.Equal(y.Call.StartedAt) || x.Call.DurationSec != y.Call.DurationSec || x.Kind != y.Kind {
			t.Fatalf("sample %d differs: %+v vs %+v", i, x, y)
		}
	}
	c := Generate(small(8, p))
	same := len(c.Samples) == len(a.Samples)
	if same {
		for i := range a.Samples {
			if a.Samples[i].Call.Caller != c.Samples[i].Call.Caller {
				same = false
				break
			}
		}
	}
	if same {
		t.Fatal("different seeds must give different data")
	}
}

func TestStructure(t *testing.T) {
	p := testPlan(t)
	cfg := small(1, p)
	ds := Generate(cfg)
	cfg.defaults()
	seen := map[string]bool{}
	kinds := map[Kind]int{}
	var prev time.Time
	fraud := 0
	for i, s := range ds.Samples {
		c := s.Call
		if seen[c.CallID] {
			t.Fatalf("duplicate call_id %s", c.CallID)
		}
		seen[c.CallID] = true
		if i > 0 && c.StartedAt.Before(prev) {
			t.Fatal("samples must be sorted by time")
		}
		prev = c.StartedAt
		if c.Caller == c.Callee {
			t.Fatalf("self call %s", c.Caller)
		}
		if c.DurationSec < 0 || c.DurationSec > 7200 {
			t.Fatalf("duration %d", c.DurationSec)
		}
		if c.Answered == nil || *c.Answered != (c.DurationSec > 0) {
			t.Fatalf("answered flag inconsistent: %+v", c)
		}
		if _, err := phone.Parse(c.Callee); err != nil {
			t.Fatalf("callee %q: %v", c.Callee, err)
		}
		if _, err := phone.Parse(c.Caller); err != nil {
			t.Fatalf("caller %q: %v", c.Caller, err)
		}
		if s.Fraud != s.Kind.IsFraud() {
			t.Fatal("label must match kind")
		}
		if s.Fraud {
			fraud++
		}
		kinds[s.Kind]++
	}
	for _, k := range append(append([]Kind{}, LegitKinds...), FraudKinds...) {
		if kinds[k] == 0 {
			t.Errorf("no samples of kind %s", k)
		}
	}
	if fraud == 0 || fraud == len(ds.Samples) {
		t.Fatalf("both classes must be present, fraud=%d of %d", fraud, len(ds.Samples))
	}
	end := cfg.Start.Add(time.Duration(2*24+12) * time.Hour)
	for _, s := range ds.Samples {
		if s.Call.StartedAt.Before(cfg.Start) || s.Call.StartedAt.After(end) {
			t.Fatalf("call outside period: %v", s.Call.StartedAt)
		}
	}
	if len(ds.Allowlist) == 0 {
		t.Fatal("banks must produce allowlist entries")
	}
}

func TestFraudPatternsAreWhatTheyClaim(t *testing.T) {
	p := testPlan(t)
	ds := Generate(small(3, p))
	type stat struct{ calls, unanswered, foreign, short int }
	st := map[Kind]*stat{}
	for _, s := range ds.Samples {
		x := st[s.Kind]
		if x == nil {
			x = &stat{}
			st[s.Kind] = x
		}
		x.calls++
		if s.Call.DurationSec == 0 {
			x.unanswered++
		}
		if s.Call.SrcCountry != "RU" && s.Call.SrcCountry != "" {
			x.foreign++
		}
		if s.Call.DurationSec > 0 && s.Call.DurationSec < 10 {
			x.short++
		}
	}
	if o := st[KindOneRing]; o.unanswered != o.calls || o.foreign != o.calls {
		t.Fatalf("one_ring must be all unanswered foreign: %+v", o)
	}
	if sp := st[KindSpoofBurst]; sp.foreign != sp.calls {
		t.Fatalf("spoof_burst must come from abroad: %+v", sp)
	}
	if r := st[KindRegular]; float64(r.unanswered)/float64(r.calls) > 0.3 {
		t.Fatalf("regular users answer most calls: %+v", r)
	}
	// роумер входит в сеть как домашний абонент; иностранный вход — редкие легитимные SIP-транки
	roam := st[KindRoamer]
	if roam.calls == 0 || float64(roam.foreign)/float64(roam.calls) > 0.5 {
		t.Fatalf("roamers must mostly look domestic: %+v", roam)
	}
}

func TestSpoofBurstUnallocatedShare(t *testing.T) {
	p := testPlan(t)
	ds := Generate(Config{Seed: 5, Plan: p, Scale: 0.05, Days: 2, SpoofBurst: 60, Regular: -1, Heavy: -1, CallCenters: -1,
		BankNotify: -1, Couriers: -1, Roamers: -1, ForeignCallers: -1, CorpMulti: -1, Emergency: -1, Robocall: -1,
		OneRing: -1, FanGroups: -1, SimFarms: -1, ColdSpam: -1})
	callers := map[string]bool{}
	for _, s := range ds.Samples {
		callers[s.Call.Caller] = true
	}
	unalloc := 0
	for c := range callers {
		n, _ := phone.Parse(c)
		if _, ok := p.Lookup(n); !ok {
			unalloc++
		}
	}
	if unalloc == 0 || unalloc == len(callers) {
		t.Fatalf("spoof callers should mix unallocated (%d) and real (%d total) numbers", unalloc, len(callers))
	}
}

// На реальном масштабе обычные абоненты дают основную часть трафика, а мошенничество — заметную,
// но меньшую долю: иначе метрики (в том числе FPR по трудным типам) не имеют смысла.
func TestDefaultMixIsRealistic(t *testing.T) {
	ds := Generate(Config{Seed: 3, Plan: testPlan(t), Days: 2})
	counts := map[Kind]int{}
	fraud := 0
	for _, s := range ds.Samples {
		counts[s.Kind]++
		if s.Fraud {
			fraud++
		}
	}
	n := float64(len(ds.Samples))
	if share := float64(counts[KindRegular]) / n; share < 0.5 {
		t.Fatalf("ordinary subscribers must dominate traffic, got %.2f", share)
	}
	if share := float64(fraud) / n; share < 0.03 || share > 0.25 {
		t.Fatalf("fraud share %.3f out of the intended range", share)
	}
	hard := counts[KindHeavy] + counts[KindCallCenter] + counts[KindBankNotify] + counts[KindCorpMulti]
	if float64(hard)/n > 0.3 {
		t.Fatalf("hard legit actors dominate traffic: %.2f", float64(hard)/n)
	}
}

func TestZeroAndNegativeCounts(t *testing.T) {
	p := testPlan(t)
	ds := Generate(Config{Seed: 1, Plan: p, Days: 1, Regular: 3, Heavy: -1, CallCenters: -1, BankNotify: -1, Couriers: -1,
		Roamers: -1, ForeignCallers: -1, CorpMulti: -1, Emergency: -1, SpoofBurst: -1, Robocall: -1, OneRing: -1,
		FanGroups: -1, SimFarms: -1, ColdSpam: -1})
	for _, s := range ds.Samples {
		if s.Kind != KindRegular {
			t.Fatalf("negative count must disable kind, got %s", s.Kind)
		}
	}
	if len(ds.Samples) == 0 {
		t.Fatal("3 regular users must produce calls")
	}
}

func TestKindHelpers(t *testing.T) {
	if !KindFan.IsFraud() || KindCallCenter.IsFraud() {
		t.Fatal("IsFraud mismatch")
	}
	if len(FraudKinds) != 6 || len(LegitKinds) != 9 {
		t.Fatal("kind lists changed")
	}
}
