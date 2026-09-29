package engine

import (
	"encoding/json"
	"math"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/decision/explain"
)

// semanticallyEqual сравнивает два JSON как значения (порядок ключей и форма записи чисел не важны).
func semanticallyEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatalf("AppendJSON produced invalid JSON: %v\n%s", err, got)
	}
	if err := json.Unmarshal(want, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("AppendJSON differs from encoding/json:\n got:  %s\n want: %s", got, want)
	}
}

func full() Response {
	return Response{
		CallID: "c-1", Decision: "review", Score: 0.1511,
		Reasons: []explain.Reason{
			{Factor: "spoof", Value: 1, Contribution: 3, Effect: "raises", Text: "российский номер при иностранном входе"},
			{Factor: "call_duration", Value: 6, Contribution: -0.544, Effect: "lowers", Text: "длительность 6 с"},
		},
		Signals:   []string{"spoof", "burst"},
		Caller:    Party{Masked: "+7 495 ***-**-12", Country: "RU", Region: "Москва и Московская область", Operator: `ПАО "МТС"`},
		Callee:    Party{Masked: "+7 916 ***-**-83", Country: "RU"},
		SafeClass: "allowlisted", BlockSuppressed: true, RuleFloor: true, Duplicate: true,
		Stage: "ml", ModelVersion: "catboost-1", NumplanVersion: "abc", LatencyUS: 1234,
	}
}

func TestAppendJSONMatchesEncodingJSON(t *testing.T) {
	cases := map[string]Response{
		"full":        full(),
		"empty":       {Reasons: []explain.Reason{}},
		"allow":       {CallID: "x", Decision: "allow", Stage: "linear", ModelVersion: "m", Reasons: []explain.Reason{}, Caller: Party{Masked: "***"}},
		"nil reasons": {CallID: "n"},
		"emergency":   {CallID: "e", Decision: "allow", SafeClass: "emergency", Reasons: []explain.Reason{}, Stage: "linear"},
	}
	for name, r := range cases {
		r := r
		got := r.AppendJSON(nil)
		if name == "nil reasons" {
			// Намеренное отличие от encoding/json (он пишет null): контракт API — reasons всегда массив.
			if !strings.Contains(string(got), `"reasons":[]`) {
				t.Fatalf("a nil reasons slice must be written as an empty array: %s", got)
			}
			continue
		}
		want, err := json.Marshal(&r)
		if err != nil {
			t.Fatal(err)
		}
		semanticallyEqual(t, got, want)
	}
}

func TestAppendJSONRoundTripsToTheSameStruct(t *testing.T) {
	r := full()
	var back Response
	if err := json.Unmarshal(r.AppendJSON(nil), &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, r) {
		t.Fatalf("round trip:\n got  %+v\n want %+v", back, r)
	}
}

func TestStringEscaping(t *testing.T) {
	nasty := []string{
		"", `a"b`, `back\slash`, "line\nbreak\r\ttab", "\x00\x01\x1f", "кириллица и emoji 😀", "  ",
		"<script>&</script>", "invalid \xff\xfe utf8", "trailing \xc3", strings.Repeat("длинная строка ", 500), "\u007f",
	}
	for _, s := range nasty {
		got := appendString(nil, s)
		var back string
		if err := json.Unmarshal(got, &back); err != nil {
			t.Fatalf("%q → invalid JSON %s: %v", s, got, err)
		}
		want, _ := json.Marshal(s)
		var wantBack string
		_ = json.Unmarshal(want, &wantBack)
		if back != wantBack {
			t.Fatalf("%q: decoded %q, encoding/json gives %q", s, back, wantBack)
		}
	}
}

func TestRandomStringsAgreeWithEncodingJSON(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	for i := 0; i < 5000; i++ {
		n := rng.IntN(40)
		buf := make([]byte, n)
		for j := range buf {
			buf[j] = byte(rng.IntN(256)) // в том числе некорректный UTF-8 и управляющие символы
		}
		s := string(buf)
		var a, b string
		if err := json.Unmarshal(appendString(nil, s), &a); err != nil {
			t.Fatalf("invalid JSON for %q: %v", s, err)
		}
		want, _ := json.Marshal(s)
		_ = json.Unmarshal(want, &b)
		if a != b {
			t.Fatalf("%q: %q vs %q", s, a, b)
		}
	}
}

func TestFloatFormatting(t *testing.T) {
	for _, f := range []float64{0, 1, -1, 0.1511, 0.0001, 1e-7, 1.5e-9, 123456789.125, 1e20, 1e21, 2.5e30, -3.75e-8, math.MaxFloat64, math.SmallestNonzeroFloat64, 100, 0.3} {
		got := string(appendFloat(nil, f))
		want, _ := json.Marshal(f)
		var a, b float64
		if err := json.Unmarshal([]byte(got), &a); err != nil {
			t.Fatalf("%v → %q is not JSON: %v", f, got, err)
		}
		_ = json.Unmarshal(want, &b)
		if a != b {
			t.Fatalf("%v: %q vs %s", f, got, want)
		}
		if got != string(want) {
			t.Fatalf("%v: representation differs from encoding/json: %q vs %s", f, got, want)
		}
	}
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if string(appendFloat(nil, bad)) != "0" {
			t.Fatalf("non-finite %v must be written as 0", bad)
		}
	}
}

func TestAppendJSONReusesBuffer(t *testing.T) {
	r := full()
	buf := make([]byte, 0, 2048)
	first := string(r.AppendJSON(buf))
	second := string(r.AppendJSON(buf[:0]))
	if first != second {
		t.Fatal("output must not depend on buffer contents")
	}
	if allocs := testing.AllocsPerRun(100, func() { buf = r.AppendJSON(buf[:0]) }); allocs != 0 {
		t.Fatalf("AppendJSON into a big enough buffer must not allocate, got %v", allocs)
	}
}

func FuzzAppendJSON(f *testing.F) {
	f.Add("c-1", "review", "текст \"с кавычками\"", 0.15)
	f.Add("", "", "\x00\xff", math.MaxFloat64)
	f.Fuzz(func(t *testing.T, id, decision, text string, score float64) {
		r := Response{CallID: id, Decision: decision, Score: score, Reasons: []explain.Reason{{Factor: id, Text: text, Value: score, Contribution: -score}}}
		var back map[string]any
		if err := json.Unmarshal(r.AppendJSON(nil), &back); err != nil {
			t.Fatalf("invalid JSON for %+v: %v", r, err)
		}
	})
}
