package numplan

import (
	"strings"
	"testing"

	"github.com/sanchyous/redflag-antifraud/internal/phone"
)

// Фрагмент в формате реального реестра (BOM, заголовок, неэкранированные кавычки, "-" в регионе).
const fixture = "\ufeffАВС/ DEF;От;До;Емкость;Оператор;Регион;Территория ГАР;ИНН\n" +
	"495;0000000;0009999;10000;ПАО МГТС;г. Москва;Город Москва;7710016640\n" +
	"495;0010000;0014999;5000;ООО \"ТЕЛЕСТОР\";г. Москва;Город Москва;7811212947\n" +
	"401;2200000;2200999;1000;АО \"МТТ\";г. Калининград|Калининградская обл.;г.о. город Калининград|Калининградская область;7705017253\n" +
	"916;0000000;4999999;5000000;ПАО \"МегаФон\";г. Москва и Московская область;Город Москва, Московская область;7812014560\n" +
	"916;5000000;9999999;5000000;ПАО \"Мобильные ТелеСистемы\";г. Москва и Московская область;Город Москва, Московская область;7740000076\n" +
	"900;0062000;0062999;1000;ООО \"Т2 МОБАЙЛ\";-;Ростовская область;7743895280\n" +
	"901;0000000;0999999;1000000;ООО \"Т2 МОБАЙЛ\";-;Краснодарский край;7743895280\n" +
	"800;1000000;1009999;10000;ПАО \"Ростелеком\";Российская Федерация;Российская Федерация;7707049388\n" +
	"битая;строка\n" +
	"999;0000010;0000001;0;ООО Обратный;-;-;1\n" // to < from → пропуск

func mustPlan(t *testing.T, csvs ...string) *Plan {
	t.Helper()
	b := NewBuilder()
	for _, c := range csvs {
		if err := b.AddCSV(strings.NewReader(c)); err != nil {
			t.Fatal(err)
		}
	}
	p, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func num(t *testing.T, s string) phone.Number {
	t.Helper()
	n, err := phone.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLoadStats(t *testing.T) {
	p := mustPlan(t, fixture)
	if p.Stats.Rows != 8 || p.Stats.Skipped != 2 || p.Stats.Overlaps != 0 || p.Stats.Files != 1 {
		t.Fatalf("stats = %+v", p.Stats)
	}
	if p.Size() != 8 || len(p.Version) != 12 {
		t.Fatalf("size=%d version=%q", p.Size(), p.Version)
	}
}

func TestLookupFull(t *testing.T) {
	p := mustPlan(t, fixture)
	cases := []struct {
		num, op, region string
		nonGeo          bool
	}{
		{"+7 495 000-99-99", "ПАО МГТС", "Москва и Московская область", false},         // верхняя граница
		{"+7 495 001-00-00", "ООО \"ТЕЛЕСТОР\"", "Москва и Московская область", false}, // нижняя граница второго
		{"+7 495 001-49-99", "ООО \"ТЕЛЕСТОР\"", "Москва и Московская область", false},
		{"+7 401 220-05-00", "АО \"МТТ\"", "Калининградская область", false}, // сегмент + обл.
		{"+7 916 123-45-67", "ПАО \"МегаФон\"", "Москва и Московская область", false},
		{"+7 916 500-00-00", "ПАО \"Мобильные ТелеСистемы\"", "Москва и Московская область", false},
		{"+7 900 006-29-99", "ООО \"Т2 МОБАЙЛ\"", "Ростовская область", false},  // "-" → территория
		{"8 800 100-05-55", "ПАО \"Ростелеком\"", "Российская Федерация", true}, // безгеографический
	}
	for _, tc := range cases {
		info, ok := p.Lookup(num(t, tc.num))
		if !ok || info.Operator != tc.op || info.Region != tc.region || info.NonGeo != tc.nonGeo {
			t.Fatalf("Lookup(%s) = %+v,%v; want %s / %s / nonGeo=%v", tc.num, info, ok, tc.op, tc.region, tc.nonGeo)
		}
		if info.MultiOperator || info.MultiRegion {
			t.Fatalf("Lookup(%s): unexpected Multi flags %+v", tc.num, info)
		}
	}
}

func TestLookupMiss(t *testing.T) {
	p := mustPlan(t, fixture)
	for _, s := range []string{
		"+7 495 002-00-00", // дыра между диапазонами
		"+49 30 12345678",  // не российский
		"+7 701 123-45-67", // Казахстан
		"+7 999 000-00-00", // кода нет в справочнике
		"112",              // короткий
	} {
		n, err := phone.Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if info, ok := p.Lookup(n); ok {
			t.Fatalf("Lookup(%s) = %+v, want miss", s, info)
		}
	}
}

func TestLookupMasked(t *testing.T) {
	p := mustPlan(t, fixture)
	// Все диапазоны кода 495 — Москва, но операторов два → регион известен, оператор — нет.
	info, ok := p.Lookup(num(t, "+7 495 ***-**-12"))
	if !ok || info.Region != "Москва и Московская область" || info.Operator != "" || !info.MultiOperator || info.MultiRegion {
		t.Fatalf("495 masked = %+v,%v", info, ok)
	}
	// Один регион и два оператора под кодом 916.
	info, ok = p.Lookup(num(t, "+7 916 ***-**-83"))
	if !ok || info.Region != "Москва и Московская область" || !info.MultiOperator {
		t.Fatalf("916 masked = %+v,%v", info, ok)
	}
	// Известна одна цифра после кода → диапазон сужается до одного оператора.
	info, ok = p.Lookup(num(t, "+7 916 5** ** 83"))
	if !ok || info.Operator != "ПАО \"Мобильные ТелеСистемы\"" || info.MultiOperator {
		t.Fatalf("916 5 masked = %+v,%v", info, ok)
	}
	// Слишком короткий известный префикс.
	if _, ok := p.LookupPrefix("49"); ok {
		t.Fatal("prefix shorter than 3 must not resolve")
	}
	if _, ok := p.LookupPrefix("49x"); ok {
		t.Fatal("non-digit prefix must not resolve")
	}
}

func TestMultiRegionUnderCode(t *testing.T) {
	p := mustPlan(t,
		"АВС/ DEF;От;До;Емкость;Оператор;Регион;Территория ГАР;ИНН\n"+
			"902;0000000;4999999;5000000;ПАО \"А\";-;Самарская область;1\n"+
			"902;5000000;9999999;5000000;ПАО \"А\";-;Пермский край;1\n")
	info, ok := p.LookupPrefix("902")
	if !ok || info.Region != "" || !info.MultiRegion || info.MultiOperator || info.Operator != "ПАО \"А\"" {
		t.Fatalf("info = %+v,%v", info, ok)
	}
}

func TestOverlapsDetected(t *testing.T) {
	p := mustPlan(t,
		"АВС/ DEF;От;До;Емкость;Оператор;Регион;Территория ГАР;ИНН\n"+
			"902;0000000;0000010;11;ПАО \"А\";-;Самарская область;1\n"+
			"902;0000005;0000020;16;ПАО \"Б\";-;Самарская область;2\n")
	if p.Stats.Overlaps != 1 {
		t.Fatalf("overlaps = %d", p.Stats.Overlaps)
	}
}

func TestBuildEmptyFails(t *testing.T) {
	b := NewBuilder()
	if err := b.AddCSV(strings.NewReader("АВС/ DEF;От;До\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(); err == nil {
		t.Fatal("empty plan must fail")
	}
}

func TestVersionStableAcrossFileOrder(t *testing.T) {
	a := "АВС/ DEF;От;До;Емкость;Оператор;Регион;Территория ГАР;ИНН\n495;0000000;0009999;1;ПАО МГТС;г. Москва;-;1\n"
	b := "АВС/ DEF;От;До;Емкость;Оператор;Регион;Территория ГАР;ИНН\n916;0000000;0009999;1;ПАО X;г. Москва;-;2\n"
	if mustPlan(t, a, b).Version != mustPlan(t, b, a).Version {
		t.Fatal("version must not depend on file order")
	}
	if mustPlan(t, a, b).Version == mustPlan(t, a).Version {
		t.Fatal("version must change with content")
	}
}

func TestNormRegion(t *testing.T) {
	cases := []struct {
		region, terr, want string
		nonGeo             bool
	}{
		{"г. Москва", "Город Москва", "Москва и Московская область", false},
		{"р-н Красногорский|Московская обл.", "г.о. Красногорск|Московская область", "Москва и Московская область", false},
		{"г. Санкт-Петербург", "Город Санкт-Петербург", "Санкт-Петербург и Ленинградская область", false},
		{"г. Москва и Московская область", "Город Москва, Московская область", "Москва и Московская область", false},
		{"г. Севастополь", "Город Севастополь", "г. Севастополь", false},
		{"-", "Краснодарский край", "Краснодарский край", false},
		{"", "Краснодарский край", "Краснодарский край", false},
		{"г. Казань|Республика Татарстан", "", "Республика Татарстан", false},
		{"Ростовская обл.", "", "Ростовская область", false},
		{"Российская Федерация, кроме Чеченской Республики", "", "Российская Федерация", true},
		{"-", "-", "неизвестно", false},
	}
	for _, tc := range cases {
		got, ng := normRegion(tc.region, tc.terr)
		if got != tc.want || ng != tc.nonGeo {
			t.Fatalf("normRegion(%q,%q) = %q,%v; want %q,%v", tc.region, tc.terr, got, ng, tc.want, tc.nonGeo)
		}
	}
}

func TestLoadDirErrors(t *testing.T) {
	if _, err := LoadDir(t.TempDir()); err == nil {
		t.Fatal("empty dir must fail")
	}
}

func BenchmarkLookup(b *testing.B) {
	bl := NewBuilder()
	_ = bl.AddCSV(strings.NewReader(fixture))
	p, _ := bl.Build()
	n, _ := phone.Parse("+7 916 123-45-67")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Lookup(n)
	}
}
