package phone

import (
	"errors"
	"strings"
	"testing"
)

func TestParseNormalization(t *testing.T) {
	cases := []struct {
		in       string
		wantE164 string
		wantISO  string
		wantNat  string
	}{
		{"+7 (916) 123-45-67", "+79161234567", "RU", "9161234567"},
		{"89161234567", "+79161234567", "RU", "9161234567"},
		{"79161234567", "+79161234567", "RU", "9161234567"},
		{"9161234567", "+79161234567", "RU", "9161234567"},
		{"4951234567", "+74951234567", "RU", "4951234567"},
		{"8 800 555-35-35", "+78005553535", "RU", "8005553535"},
		{"+7 701 123 45 67", "+77011234567", "KZ", "7011234567"},
		{"8 10 49 30 12345678", "+493012345678", "DE", "3012345678"},
		{"0049 30 12345678", "+493012345678", "DE", "3012345678"},
		{"+1 202 555 0143", "+12025550143", "NANP", "2025550143"},
		{"+44 20 7946 0958", "+442079460958", "GB", "2079460958"},
		{"+380 44 123 45 67", "+380441234567", "UA", "441234567"},
		{"+375291234567", "+375291234567", "BY", "291234567"},
		{"493012345678", "+493012345678", "DE", "3012345678"}, // E.164 без плюса
		{"  +7 916.123.45.67 ", "+79161234567", "RU", "9161234567"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			n, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if n.E164() != tc.wantE164 || n.ISO != tc.wantISO || n.National != tc.wantNat {
				t.Fatalf("Parse(%q) = %+v (%s), want %s/%s/%s", tc.in, n, n.E164(), tc.wantE164, tc.wantISO, tc.wantNat)
			}
			if !n.Complete() || n.Short || n.Masked {
				t.Fatalf("flags wrong: %+v", n)
			}
		})
	}
}

func TestParseShort(t *testing.T) {
	for _, in := range []string{"112", "103", "0900", "900", "10111"} {
		n, err := Parse(in)
		if err != nil || !n.Short || n.E164() != in || n.CC != "" {
			t.Fatalf("Parse(%q) = %+v, %v", in, n, err)
		}
	}
}

func TestParseMasked(t *testing.T) {
	n, err := Parse("+7 495 ***-**-12")
	if err != nil {
		t.Fatal(err)
	}
	if !n.Masked || n.Complete() || n.ISO != "RU" || n.National != "495*****12" {
		t.Fatalf("got %+v", n)
	}
	if p, ok := n.Prefix(3); !ok || p != "495" {
		t.Fatalf("Prefix(3) = %q,%v", p, ok)
	}
	if _, ok := n.Prefix(5); ok {
		t.Fatal("Prefix over masked digits must be unknown")
	}
	if n.Mask() != "+7 495 ***-**-12" {
		t.Fatalf("Mask = %q", n.Mask())
	}
	if _, ok := n.ID([]byte("k")); ok {
		t.Fatal("masked number must have no ID")
	}
	n2, err := Parse("+7 916 ***-**-83")
	if err != nil || n2.Mask() != "+7 916 ***-**-83" {
		t.Fatalf("got %+v %v", n2, err)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		in   string
		want error
	}{
		{"", ErrEmpty},
		{"   ", ErrEmpty},
		{"abc", ErrInvalid},
		{"+7 916 12x 45 67", ErrInvalid},
		{"+", ErrInvalid},
		{"+7 916 1234567 89012", ErrTooLong},
		{"+79161", ErrInvalid},           // слишком коротко для международного
		{"+21 0123456789", ErrInvalid},   // +7 с невалидным вторым знаком/нет страны
		{"+7 116 123 45 67", ErrInvalid}, // +7 1xx не существует
		{"+800 1234 5678", ErrInvalid},   // международный сервис — не поддерживаем
		{"1*2", ErrInvalid},              // маскированный короткий
		{"7+9161234567", ErrInvalid},     // плюс не в начале
		{"+999 123 45 67 89", ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			_, err := Parse(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse(%q) err = %v, want %v", tc.in, err, tc.want)
			}
		})
	}
}

func TestMask(t *testing.T) {
	n, _ := Parse("+7 916 123-45-67")
	if got := n.Mask(); got != "+7 916 ***-**-67" {
		t.Fatalf("Mask = %q", got)
	}
	if strings.Contains(n.Mask(), "1234") {
		t.Fatal("mask leaks digits")
	}
	de, _ := Parse("+493012345678")
	if got := de.Mask(); got != "+49 301 *****-78" {
		t.Fatalf("Mask DE = %q", got)
	}
	sh, _ := Parse("112")
	if sh.Mask() != "112" {
		t.Fatalf("short mask = %q", sh.Mask())
	}
}

func TestID(t *testing.T) {
	a, _ := Parse("+7 916 123-45-67")
	b, _ := Parse("89161234567")
	c, _ := Parse("+7 916 123-45-68")
	k := []byte("secret")
	ia, ok := a.ID(k)
	if !ok || len(ia) != 32 {
		t.Fatalf("ID = %q,%v", ia, ok)
	}
	ib, _ := b.ID(k)
	ic, _ := c.ID(k)
	if ia != ib {
		t.Fatal("different formats of the same number must yield the same ID")
	}
	if ia == ic {
		t.Fatal("different numbers must yield different IDs")
	}
	other, _ := a.ID([]byte("other"))
	if other == ia {
		t.Fatal("ID must depend on key")
	}
	sh, _ := Parse("112")
	if _, ok := sh.ID(k); ok {
		t.Fatal("short number must have no ID")
	}
}

func TestCountryTablesConsistent(t *testing.T) {
	for c := range codes2 {
		if len(c) != 2 {
			t.Fatalf("bad codes2 key %q", c)
		}
		if _, ok := codes3[c+"0"]; ok {
			// 2-значный код не может быть префиксом 3-значного
			t.Fatalf("prefix clash: %s", c)
		}
	}
	for c := range codes3 {
		if len(c) != 3 {
			t.Fatalf("bad codes3 key %q", c)
		}
		if _, ok := codes2[c[:2]]; ok {
			t.Fatalf("prefix clash: %s vs %s", c, c[:2])
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"+7 916 123-45-67", "112", "8 10 49 30", "+7 495 ***-**-12", "", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := Parse(s)
		if err != nil {
			return
		}
		if n.Digits == "" {
			t.Fatalf("empty digits without error for %q", s)
		}
		_ = n.Mask()
		_ = n.E164()
	})
}
