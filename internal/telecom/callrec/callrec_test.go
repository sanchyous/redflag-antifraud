package callrec

import (
	"reflect"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 14, 11, 42, 0, 0, time.UTC)

func ptr(b bool) *bool { return &b }

func TestValidate(t *testing.T) {
	ok := Call{CallID: "c1", Caller: "+7 495 ***-**-12", Callee: "+7 916 ***-**-83", StartedAt: now, DurationSec: 6}
	cases := []struct {
		name   string
		mutate func(c *Call)
		want   []string
	}{
		{"valid", func(c *Call) {}, nil},
		{"zero started_at allowed", func(c *Call) { c.StartedAt = time.Time{} }, nil},
		{"empty caller allowed (anonymous)", func(c *Call) { c.Caller = "" }, nil},
		{"no call_id", func(c *Call) { c.CallID = "" }, []string{"call_id_required"}},
		{"long call_id", func(c *Call) { c.CallID = string(make([]byte, 129)) }, []string{"call_id_too_long"}},
		{"no callee", func(c *Call) { c.Callee = "  " }, []string{"callee_required"}},
		{"negative duration", func(c *Call) { c.DurationSec = -1 }, []string{"duration_negative"}},
		{"huge duration", func(c *Call) { c.DurationSec = 86401 }, []string{"duration_too_long"}},
		{"future", func(c *Call) { c.StartedAt = now.Add(2 * time.Hour) }, []string{"started_at_in_future"}},
		{"skew tolerated", func(c *Call) { c.StartedAt = now.Add(30 * time.Minute) }, nil},
		{"bad conn", func(c *Call) { c.ConnType = "carrier-pigeon" }, []string{"conn_type_invalid"}},
		{"unanswered with duration", func(c *Call) { c.Answered = ptr(false) }, []string{"unanswered_with_duration"}},
		{"bad country", func(c *Call) { c.SrcCountry = "RUS" }, []string{"src_country_invalid"}},
		{"multiple", func(c *Call) { c.CallID = ""; c.DurationSec = -5 }, []string{"call_id_required", "duration_negative"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ok
			tc.mutate(&c)
			if got := c.Validate(now, time.Hour); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Validate = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFutureCheckDisabledByDefault(t *testing.T) {
	c := Call{CallID: "c", Callee: "1", StartedAt: now.Add(1000 * time.Hour)}
	if errs := c.Validate(now, 0); len(errs) != 0 {
		t.Fatalf("maxFuture=0 must disable the check: %v", errs)
	}
	if errs := c.Validate(now, time.Hour); len(errs) != 1 || errs[0] != "started_at_in_future" {
		t.Fatalf("enabled check: %v", errs)
	}
}

func TestIsAnswered(t *testing.T) {
	if (&Call{DurationSec: 5}).IsAnswered() != true || (&Call{DurationSec: 0}).IsAnswered() != false {
		t.Fatal("default answered = duration > 0")
	}
	if !(&Call{Answered: ptr(true)}).IsAnswered() || (&Call{Answered: ptr(false)}).IsAnswered() {
		t.Fatal("explicit answered must win")
	}
}

func TestConnType(t *testing.T) {
	for in, want := range map[string]ConnType{"": ConnUnknown, "Mobile": ConnMobile, " GSM ": ConnMobile,
		"pstn": ConnFixed, "intl": ConnInternational, "SIP": ConnVoIP} {
		if got, ok := ParseConnType(in); !ok || got != want {
			t.Fatalf("ParseConnType(%q) = %v,%v", in, got, ok)
		}
	}
	if _, ok := ParseConnType("x"); ok {
		t.Fatal("unknown conn type must be rejected")
	}
	if ConnVoIP.String() != "voip" || ConnType(99).String() != "unknown" {
		t.Fatal("String mismatch")
	}
}

func TestEventHas(t *testing.T) {
	e := Event{Flags: FlagAnswered | FlagSpoof}
	if !e.Has(FlagSpoof) || e.Has(FlagHangup1s) {
		t.Fatal("Has mismatch")
	}
}
