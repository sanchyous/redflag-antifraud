package enrich

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/callrec"
	"github.com/sanchyous/redflag-antifraud/internal/numplan"
)

const csvHead = "АВС/ DEF;От;До;Емкость;Оператор;Регион;Территория ГАР;ИНН\n"

func testPlan(t testing.TB) *numplan.Plan {
	b := numplan.NewBuilder()
	err := b.AddCSV(strings.NewReader(csvHead +
		"495;0000000;9999999;10000000;ПАО МГТС;г. Москва;Город Москва;7710016640\n" +
		"916;0000000;4999999;5000000;ПАО \"МегаФон\";г. Москва и Московская область;Город Москва, Московская область;7812014560\n" +
		"916;5000000;9999999;5000000;ПАО \"МТС\";г. Москва и Московская область;Город Москва, Московская область;7740000076\n" +
		"913;0000000;0999999;1000000;ПАО \"МТС\";-;Кемеровская область - Кузбасс;7740000076\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var start = time.Date(2026, 10, 14, 11, 42, 0, 0, time.FixedZone("MSK", 3*3600))

func base() callrec.Call {
	return callrec.Call{CallID: "c1", Caller: "+7 916 600-00-01", Callee: "+7 913 000-00-83", StartedAt: start, DurationSec: 6}
}

func TestEnrichBasic(t *testing.T) {
	e := New(testPlan(t), nil)
	c := base()
	r, err := e.Enrich(&c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Caller.Operator != `ПАО "МТС"` || r.Caller.Brand != BrandMTS || r.Caller.Region != "Москва и Московская область" {
		t.Fatalf("caller = %+v", r.Caller)
	}
	if r.Callee.Region != "Кемеровская область - Кузбасс" || r.Callee.RegionID == r.Caller.RegionID {
		t.Fatalf("callee = %+v", r.Callee)
	}
	if r.LocalHour != 11 || r.Night || r.ForeignIngress || r.Spoof || r.CallerUnallocated || r.OperatorMismatch {
		t.Fatalf("unexpected signals: %+v", r)
	}
	ev := r.Event
	if !ev.Has(callrec.FlagAnswered) || ev.Has(callrec.FlagHangup1s) || ev.DurSec != 6 || ev.TS != start.Unix() {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Caller != 79166000001 || ev.Callee != 79130000083 || ev.CallerRegion != r.Caller.RegionID {
		t.Fatalf("event keys = %+v", ev)
	}
}

func TestSpoofScenarioFromTZ(t *testing.T) {
	// Пример из ТЗ: +7 495 ***-**-12 → +7 916 ***-**-83, 6 секунд, вход из-за рубежа.
	e := New(testPlan(t), nil)
	c := callrec.Call{CallID: "tz", Caller: "+7 495 ***-**-12", Callee: "+7 916 ***-**-83", StartedAt: start, DurationSec: 6, SrcCountry: "de"}
	r, err := e.Enrich(&c)
	if err != nil {
		t.Fatal(err)
	}
	if !r.ForeignIngress || !r.Spoof || !r.Event.Has(callrec.FlagSpoof) || r.SrcCountry != "DE" {
		t.Fatalf("spoof not detected: %+v", r)
	}
	if r.CallerUnallocated {
		t.Fatal("masked caller must not be flagged as unallocated")
	}
	if r.Caller.Region != "Москва и Московская область" {
		t.Fatalf("masked region = %q", r.Caller.Region)
	}
	if r.Callee.Region != "Москва и Московская область" || r.Callee.Operator != "" {
		t.Fatalf("masked callee = %+v", r.Callee)
	}
}

func TestSpoofByConnType(t *testing.T) {
	e := New(testPlan(t), nil)
	c := base()
	c.ConnType = "international"
	r, _ := e.Enrich(&c)
	if !r.Spoof || !r.ForeignIngress {
		t.Fatalf("international transit with RU CLI must be spoof: %+v", r)
	}
}

func TestNoSpoofForForeignCLI(t *testing.T) {
	e := New(testPlan(t), nil)
	c := base()
	c.Caller = "+49 30 12345678"
	c.SrcCountry = "DE"
	r, _ := e.Enrich(&c)
	if !r.ForeignIngress || r.Spoof || r.CallerUnallocated {
		t.Fatalf("honest foreign call flagged: %+v", r)
	}
}

func TestCallerUnallocated(t *testing.T) {
	e := New(testPlan(t), nil)
	c := base()
	c.Caller = "+7 999 123-45-67" // кода 999 нет в справочнике
	r, _ := e.Enrich(&c)
	if !r.CallerUnallocated || !r.Event.Has(callrec.FlagCallerUnallocated) {
		t.Fatalf("unallocated not detected: %+v", r)
	}
	// Без справочника флаг не ставим: нет оснований.
	r2, _ := New(nil, nil).Enrich(&c)
	if r2.CallerUnallocated {
		t.Fatal("nil plan must not flag unallocated")
	}
}

func TestOperatorMismatch(t *testing.T) {
	e := New(testPlan(t), nil)
	c := base()
	c.SrcOperator = "Beeline"
	r, _ := e.Enrich(&c)
	if !r.OperatorMismatch || r.SrcBrand != BrandBeeline {
		t.Fatalf("mismatch not detected: %+v", r)
	}
	c.SrcOperator = "ПАО МТС"
	if r, _ = e.Enrich(&c); r.OperatorMismatch {
		t.Fatal("same brand must not mismatch")
	}
	c.SrcOperator = "Какой-то местный оператор"
	if r, _ = e.Enrich(&c); r.OperatorMismatch {
		t.Fatal("unknown brand must not mismatch")
	}
	// Иностранный вход: сравнение с российским реестром бессмысленно.
	c.SrcOperator, c.SrcCountry = "Beeline", "DE"
	if r, _ = e.Enrich(&c); r.OperatorMismatch {
		t.Fatal("mismatch must not be set for foreign ingress")
	}
}

func TestHangup1sAndUnanswered(t *testing.T) {
	e := New(testPlan(t), nil)
	c := base()
	c.DurationSec = 1
	r, _ := e.Enrich(&c)
	if !r.Event.Has(callrec.FlagHangup1s) || !r.Event.Has(callrec.FlagAnswered) {
		t.Fatalf("hangup1s: %+v", r.Event)
	}
	f := false
	c.DurationSec, c.Answered = 0, &f
	r, _ = e.Enrich(&c)
	if r.Event.Has(callrec.FlagAnswered) || r.Event.Has(callrec.FlagHangup1s) {
		t.Fatalf("unanswered: %+v", r.Event)
	}
}

func TestCallerInvalidAndAnonymous(t *testing.T) {
	e := New(testPlan(t), nil)
	for _, caller := range []string{"", "anonymous", "???"} {
		c := base()
		c.Caller = caller
		r, err := e.Enrich(&c)
		if err != nil {
			t.Fatalf("caller %q: %v", caller, err)
		}
		if !r.Event.Has(callrec.FlagCallerInvalid) || r.Event.Caller != 0 || r.Spoof {
			t.Fatalf("caller %q: %+v", caller, r)
		}
	}
}

func TestCalleeInvalid(t *testing.T) {
	c := base()
	c.Callee = "not-a-number"
	if _, err := New(nil, nil).Enrich(&c); !errors.Is(err, ErrCalleeInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestNightUsesLocalZone(t *testing.T) {
	e := New(nil, nil)
	c := base()
	c.StartedAt = time.Date(2026, 10, 14, 0, 30, 0, 0, time.UTC) // 03:30 по Москве
	r, _ := e.Enrich(&c)
	if r.LocalHour != 3 || !r.Night {
		t.Fatalf("hour=%d night=%v", r.LocalHour, r.Night)
	}
	c.StartedAt = time.Date(2026, 10, 14, 3, 30, 0, 0, time.UTC) // 06:30 по Москве
	if r, _ = e.Enrich(&c); r.Night {
		t.Fatal("06:30 local is not night")
	}
}

func TestShortNumberCaller(t *testing.T) {
	c := base()
	c.Caller = "112"
	r, err := New(testPlan(t), nil).Enrich(&c)
	if err != nil || r.Spoof || r.CallerUnallocated {
		t.Fatalf("short caller: %+v %v", r, err)
	}
}

func TestBrandByName(t *testing.T) {
	cases := map[string]Brand{"MTS": BrandMTS, "ПАО «МегаФон»": BrandMegaFon, "Tele2 Russia": BrandTele2,
		"ПАО Вымпелком": BrandBeeline, "Ростелеком": BrandRostelecom, "": BrandUnknown, "Иной": BrandUnknown}
	for in, want := range cases {
		if got := brandByName(in); got != want {
			t.Fatalf("brandByName(%q) = %v, want %v", in, got, want)
		}
	}
	if BrandMTS.String() != "МТС" || Brand(99).String() != "" {
		t.Fatal("Brand.String mismatch")
	}
}

func TestSubscriberHash(t *testing.T) {
	e := New(nil, nil)
	c := base()
	r, _ := e.Enrich(&c)
	if r.Event.Subscriber != 0 {
		t.Fatal("no subscriber_id → 0")
	}
	c.SubscriberID = "sub-1"
	a, _ := e.Enrich(&c)
	b, _ := e.Enrich(&c)
	c.SubscriberID = "sub-2"
	d, _ := e.Enrich(&c)
	if a.Event.Subscriber == 0 || a.Event.Subscriber != b.Event.Subscriber || a.Event.Subscriber == d.Event.Subscriber {
		t.Fatal("subscriber hash must be stable and distinct")
	}
}

func BenchmarkEnrich(b *testing.B) {
	e := New(testPlan(b), nil)
	c := base()
	c.SrcCountry = "DE"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enrich(&c)
	}
}
