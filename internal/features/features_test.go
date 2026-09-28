package features

import (
	"math"
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/callrec"
	"github.com/sanchyous/redflag-antifraud/internal/enrich"
	"github.com/sanchyous/redflag-antifraud/internal/graph"
	"github.com/sanchyous/redflag-antifraud/internal/window"
)

func TestNamesUniqueAndComplete(t *testing.T) {
	seen := map[string]bool{}
	for i, n := range Names {
		if n == "" {
			t.Fatalf("Names[%d] is empty", i)
		}
		if seen[n] {
			t.Fatalf("duplicate name %q", n)
		}
		seen[n] = true
	}
}

func near(a, b float32) bool { return math.Abs(float64(a-b)) < 1e-4 }

func TestBuildQuietSubscriber(t *testing.T) {
	var v Vector
	res := enrich.Result{Event: callrec.Event{DurSec: 120, Flags: callrec.FlagAnswered}}
	Build(&Input{Res: &res, Win: window.Features{Out: window.NumFeatures{Calls1h: 1, Calls24h: 2, Peers1h: 1, Peers24h: 2}}}, &v)
	if v.Raw[CallShort] != 0 || v.Raw[CallUnanswered] != 0 || v.Raw[Spoof] != 0 {
		t.Fatalf("raw = %v", v.Raw)
	}
	// мало данных: доли и «новизна» не сообщаются
	if v.Raw[OutNovelty] != 0 || v.Raw[OutShortShare] != 0 || v.Raw[OutUnansweredShare] != 0 {
		t.Fatalf("shares under min evidence must be zero: %v", v.Raw)
	}
	if !near(v.X[OutCalls24h], float32(math.Log1p(2))) || !near(v.X[CallDuration], float32(math.Log1p(120))) {
		t.Fatalf("log scaling wrong: %v", v.X)
	}
	if v.X[CallShort] != v.Raw[CallShort] {
		t.Fatal("binary features must not be log-scaled")
	}
}

func TestBuildFraudPattern(t *testing.T) {
	var v Vector
	res := enrich.Result{
		Night: true, ForeignIngress: true, Spoof: true, CallerUnallocated: true, OperatorMismatch: true,
		ConnType: callrec.ConnInternational,
		Event:    callrec.Event{DurSec: 3, Flags: callrec.FlagAnswered | callrec.FlagCallerInvalid | callrec.FlagHangup1s},
	}
	in := &Input{
		Res: &res,
		Win: window.Features{
			Out: window.NumFeatures{Calls1h: 200, Calls24h: 400, Peers1h: 200, Peers24h: 400, Regions24h: 30, RegionEntropy: 4.5,
				ShortShare: 0.9, UnansweredShare: 0.6, GapMeanSec: 18, GapCV: 0.1},
			In: window.NumFeatures{Calls1h: 3, Peers24h: 20},
		},
		Fan: graph.FanInfo{Size: 8}, InFan: true, SubNums: 12,
	}
	Build(in, &v)
	checks := map[int]float32{
		OutNovelty: 1, OutShortShare: 0.9, OutUnansweredShare: 0.6, OutGapRobot: 0.9, CallShort: 1, CallHangup1s: 1,
		CallNight: 1, ForeignIngress: 1, Spoof: 1, CallerUnallocated: 1, CallerInvalid: 1, OperatorMismatch: 1,
		ConnInternational: 1, FanMember: 1, FanSize: 8, SubscriberNumbers: 11, OutRegions24h: 30,
	}
	for idx, want := range checks {
		if !near(v.Raw[idx], want) {
			t.Fatalf("%s raw = %v, want %v", Names[idx], v.Raw[idx], want)
		}
	}
}

func TestBuildResetsPreviousVector(t *testing.T) {
	var v Vector
	v.Raw[Spoof] = 1
	v.X[Spoof] = 1
	Build(&Input{Res: &enrich.Result{}}, &v)
	if v.Raw[Spoof] != 0 || v.X[Spoof] != 0 {
		t.Fatal("Build must reset the vector")
	}
}

func TestShortThresholdAndUnanswered(t *testing.T) {
	var v Vector
	res := enrich.Result{Event: callrec.Event{DurSec: 9, Flags: callrec.FlagAnswered}}
	Build(&Input{Res: &res}, &v)
	if v.Raw[CallShort] != 1 {
		t.Fatal("9 s answered is short at default threshold 10")
	}
	res.Event.DurSec = 10
	Build(&Input{Res: &res}, &v)
	if v.Raw[CallShort] != 0 {
		t.Fatal("10 s is not short")
	}
	res.Event = callrec.Event{}
	Build(&Input{Res: &res}, &v)
	if v.Raw[CallUnanswered] != 1 || v.Raw[CallShort] != 0 {
		t.Fatal("unanswered call is not 'short'")
	}
	Build(&Input{Res: &res, ShortSec: 30, Win: window.Features{}}, &v)
}

func TestRobotNeedsEvidenceAndClamps(t *testing.T) {
	var v Vector
	res := enrich.Result{}
	Build(&Input{Res: &res, Win: window.Features{Out: window.NumFeatures{Calls1h: 3, GapMeanSec: 10, GapCV: 0}}}, &v)
	if v.Raw[OutGapRobot] != 0 {
		t.Fatal("too few calls for robot")
	}
	Build(&Input{Res: &res, Win: window.Features{Out: window.NumFeatures{Calls1h: 10, GapMeanSec: 10, GapCV: 2.5}}}, &v)
	if v.Raw[OutGapRobot] != 0 {
		t.Fatal("cv > 1 must clamp to zero")
	}
	Build(&Input{Res: &res, Win: window.Features{Out: window.NumFeatures{Calls1h: 10, GapMeanSec: 10, GapCV: 0}}}, &v)
	if v.Raw[OutGapRobot] != 1 {
		t.Fatal("perfect regularity → 1")
	}
}

func BenchmarkBuild(b *testing.B) {
	res := enrich.Result{Event: callrec.Event{DurSec: 5, Flags: callrec.FlagAnswered}}
	in := &Input{Res: &res, Win: window.Features{Out: window.NumFeatures{Calls1h: 50, Calls24h: 80, Peers24h: 70}}}
	var v Vector
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Build(in, &v)
	}
}
