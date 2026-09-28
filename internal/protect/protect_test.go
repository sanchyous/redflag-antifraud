package protect

import (
	"strings"
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/phone"
)

func p(t *testing.T, s string) phone.Number {
	t.Helper()
	n, err := phone.Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return n
}

func TestEmergencyEitherSide(t *testing.T) {
	c := New()
	person := p(t, "+7 916 123-45-67")
	for _, e := range []string{"112", "103", "101", "102", "104", "03", "0112", "911"} {
		if got := c.Classify(person, p(t, e), true); got != Emergency {
			t.Fatalf("person → %s = %v, want Emergency", e, got)
		}
		// обратный звонок диспетчера человеку
		if got := c.Classify(p(t, e), person, true); got != Emergency {
			t.Fatalf("%s → person = %v, want Emergency", e, got)
		}
	}
}

func TestServiceShort(t *testing.T) {
	c := New()
	person := p(t, "+7 916 123-45-67")
	for _, s := range []string{"900", "0611", "8800"} {
		n, err := phone.Parse(s)
		if err != nil || !n.Short {
			t.Fatalf("%s not short", s)
		}
		if got := c.Classify(person, n, true); got != ServiceShort {
			t.Fatalf("→ %s = %v", s, got)
		}
	}
}

func TestNoneForOrdinary(t *testing.T) {
	c := New()
	if got := c.Classify(p(t, "+7 916 123-45-67"), p(t, "+7 495 765-43-21"), true); got != None || got.NeverBlock() {
		t.Fatalf("got %v", got)
	}
	// невалидный CLI: звонящий не считается защищённым
	if got := c.Classify(phone.Number{}, p(t, "+7 916 123-45-67"), false); got != None {
		t.Fatalf("invalid caller: %v", got)
	}
}

func TestAllowlist(t *testing.T) {
	c := New()
	n, bad := c.LoadAllowlist(strings.NewReader(`
# банки и госорганы
+7 495 123-45-67
+7 800 555*      # префикс
+7 (49)*
+7*
мусор
`))
	if n != 2 || len(bad) != 3 {
		t.Fatalf("loaded=%d bad=%v", n, bad)
	}
	if c.Size() != 2 {
		t.Fatalf("Size = %d", c.Size())
	}
	callee := p(t, "+7 916 123-45-67")
	cases := map[string]Class{
		"+7 495 123-45-67": Allowlisted, // точный
		"+7 495 123-45-68": None,
		"+7 800 555-35-35": Allowlisted, // префикс
		"+7 800 556-00-00": None,
		"+7 499 110-00-00": None, // префикс из 3 цифр слишком широк → отвергнут
	}
	for num, want := range cases {
		if got := c.Classify(p(t, num), callee, true); got != want {
			t.Fatalf("%s = %v, want %v", num, got, want)
		}
	}
	if !Allowlisted.NeverBlock() || Allowlisted.String() != "allowlisted" || Emergency.String() != "emergency" || Class(9).String() != "" {
		t.Fatal("class helpers mismatch")
	}
}

func TestMaskedCallerNotAllowlistedByGuess(t *testing.T) {
	c := New()
	c.Add("+7 495 123*")
	m := p(t, "+7 495 ***-**-12") // известная часть "7495" короче префикса → не совпадает
	if got := c.Classify(m, p(t, "+7 916 123-45-67"), true); got != None {
		t.Fatalf("masked caller must not match a longer prefix: %v", got)
	}
}

func TestEmergencyWinsOverAllowlist(t *testing.T) {
	c := New()
	c.Add("+7 495 123*")
	if got := c.Classify(p(t, "+7 495 123-45-67"), p(t, "103"), true); got != Emergency {
		t.Fatalf("got %v", got)
	}
}

func TestIsEmergencyRaw(t *testing.T) {
	for _, s := range []string{"112", "*112", "112#", "+112", "0103", " 03 ", "*103#"} {
		if !IsEmergencyRaw(s) {
			t.Fatalf("%q must be emergency", s)
		}
	}
	for _, s := range []string{"", "abc", "1122", "+7 916 123-45-67", "900", "105", "11"} {
		if IsEmergencyRaw(s) {
			t.Fatalf("%q must not be emergency", s)
		}
	}
}
