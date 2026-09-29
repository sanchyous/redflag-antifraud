package explain

import (
	"strings"
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/scoring"
)

func TestEveryFeatureHasText(t *testing.T) {
	for i := 0; i < features.N; i++ {
		txt := Text(i, 1)
		if txt == "" || txt == features.Names[i] {
			t.Fatalf("feature %s has no human text", features.Names[i])
		}
	}
	for _, bad := range []int{-1, features.N, features.N + 99} {
		if Text(bad, 0) != "неизвестный фактор" {
			t.Fatalf("out-of-range index %d must not panic", bad)
		}
	}
}

func TestTextFormatting(t *testing.T) {
	cases := map[int]struct {
		raw  float32
		want string
	}{
		features.OutCalls1h:        {340, "340 исходящих вызовов за час"},
		features.OutShortShare:     {0.92, "92% принятых вызовов короче 10 с"},
		features.OutRegions24h:     {41, "охват 41 регионов получателей за сутки"},
		features.SubscriberNumbers: {11, "на того же абонента оформлено ещё 11 номеров"},
	}
	for f, tc := range cases {
		if got := Text(f, tc.raw); got != tc.want {
			t.Fatalf("Text(%s) = %q, want %q", features.Names[f], got, tc.want)
		}
	}
}

func TestReasonsFromExplanation(t *testing.T) {
	m := scoring.Prior()
	var v features.Vector
	v.Raw[features.OutCalls1h], v.X[features.OutCalls1h] = 340, 5.83
	v.Raw[features.Spoof], v.X[features.Spoof] = 1, 1
	v.Raw[features.CallDuration], v.X[features.CallDuration] = 3000, 8
	var ex scoring.Explanation
	m.Score(&v, &ex)

	rs := Reasons(&ex, 0.05, 5, 2)
	if len(rs) < 3 {
		t.Fatalf("reasons = %+v", rs)
	}
	if rs[0].Effect != "raises" || rs[0].Contribution <= 0 {
		t.Fatalf("first reason must raise risk: %+v", rs[0])
	}
	var sawLowers bool
	for _, r := range rs {
		if r.Text == "" || r.Factor == "" {
			t.Fatalf("incomplete reason: %+v", r)
		}
		if r.Effect == "lowers" {
			sawLowers = true
			if r.Contribution >= 0 {
				t.Fatalf("lowering reason with positive contribution: %+v", r)
			}
		}
	}
	if !sawLowers {
		t.Fatal("expected a mitigating factor (long call)")
	}
	found := false
	for _, r := range rs {
		if r.Factor == "out_calls_1h" && strings.Contains(r.Text, "340") {
			found = true
		}
	}
	if !found {
		t.Fatalf("out_calls_1h text must show the value: %+v", rs)
	}
	// порог отсекает мелочь
	if got := Reasons(&ex, 1000, 5, 2); len(got) != 0 {
		t.Fatalf("huge threshold must drop everything: %+v", got)
	}
	if got := Reasons(&ex, 0, 0, 0); len(got) != 0 {
		t.Fatalf("zero limits: %+v", got)
	}
}

func TestFromML(t *testing.T) {
	cs := []MLContribution{
		{"out_calls_1h", 340, 1.2},
		{"spoof", 1, 3.0},
		{"call_duration", 900, -0.8},
		{"novel_feature_from_future", 1, 9},
		{"call_night", 1, 0.01}, // ниже порога
		{"out_short_share", 0.9, 2.0},
	}
	rs := FromML(cs, 0.05, 2, 1)
	if len(rs) != 3 {
		t.Fatalf("reasons = %+v", rs)
	}
	if rs[0].Factor != "spoof" || rs[1].Factor != "out_short_share" || rs[0].Effect != "raises" {
		t.Fatalf("positives must be sorted by contribution and capped: %+v", rs)
	}
	if rs[2].Factor != "call_duration" || rs[2].Effect != "lowers" || rs[2].Contribution >= 0 {
		t.Fatalf("mitigating factor: %+v", rs[2])
	}
	if rs[1].Text != "90% принятых вызовов короче 10 с" {
		t.Fatalf("text = %q", rs[1].Text)
	}
	if got := FromML(nil, 0.05, 5, 5); got == nil || len(got) != 0 {
		t.Fatal("empty input must give an empty, non-nil list")
	}
}
