package ingest

import (
	"strings"
	"testing"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/telecom/callrec"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/phone"
)

func TestReadCDRBasicTypes(t *testing.T) {
	src := "02;250020582732825;8109392353;2001413931;20261001000000;3;\n" + // исходящий
		"01;;8927842361;8994988642;20261001000002;86;\n" + // входящий: реально звонил B
		"03;250016755033844;0278765243;2107897245;20261001000010;34;0255113701\n" // переадресация
	res, err := ReadCDR(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 3 || len(res.Errors) != 0 {
		t.Fatalf("%+v errs=%v", res.Records, res.Errors)
	}

	out := res.Records[0].Call
	if CDRBareNumber(out.Caller) != "8109392353" || CDRBareNumber(out.Callee) != "2001413931" ||
		out.Direction != callrec.DirOutgoing || out.IMSI == "" {
		t.Fatalf("outgoing: %+v", out)
	}

	in := res.Records[1].Call
	if CDRBareNumber(in.Caller) != "8994988642" || CDRBareNumber(in.Callee) != "8927842361" ||
		in.Direction != callrec.DirIncoming {
		t.Fatalf("incoming must swap caller/callee (B actually dialed A): %+v", in)
	}

	fwd := res.Records[2].Call
	if CDRBareNumber(fwd.Caller) != "0278765243" || CDRBareNumber(fwd.Callee) != "2107897245" ||
		CDRBareNumber(fwd.ForwardTo) != "0255113701" || fwd.Direction != callrec.DirForwarded {
		t.Fatalf("forwarded: %+v", fwd)
	}
	want := time.Date(2026, 10, 1, 0, 0, 10, 0, Loc)
	if !fwd.StartedAt.Equal(want) {
		t.Fatalf("time = %v, want %v", fwd.StartedAt, want)
	}
}

func TestReadCDRToleratesGarbageRows(t *testing.T) {
	src := strings.Join([]string{
		"02;250020582732825;8109392353;2001413931;20261001000000;3;;;", // лишние хвостовые поля — ок
		"AA;250020582732825;8109392353;2001413931;20261001000000;3;",   // неизвестный тип
		"02;250020582732825;8109392353;2001413931;20261001000000;-5;",  // отрицательная длительность
		"02;250020582732825;8109392353;2001413931;garbage;3;",          // неразбираемая дата
		"02;250020582732825;;2001413931;20261001000000;3;",             // пустой A
		"03;250020582732825;8109392353;2001413931;20261001000000;3;",   // переадресация без C
	}, "\n")
	res, err := ReadCDR(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("only the first row should parse: %+v", res.Records)
	}
	if len(res.Errors) != 5 {
		t.Fatalf("expected 5 row errors, got %d: %v", len(res.Errors), res.Errors)
	}
}

func TestNormCDRNumber(t *testing.T) {
	cases := map[string]string{
		"8991234567":   "8991234567", // как есть, валидный код
		"+78991234567": "8991234567", // +7 страна
		"78991234567":  "8991234567", // 7 без плюса
		"88991234567":  "8991234567", // 8 — трунк-префикс
		"80265438177":  "0265438177", // трунк-префикс + код с ведущим нулём
		"0265438177":   "0265438177", // код с ведущим нулём как есть
		"12345":        "",           // слишком коротко
		"9991234567":   "",           // неизвестный код
	}
	for in, want := range cases {
		got, ok := normCDRNumber(in)
		if want == "" {
			if ok {
				t.Fatalf("normCDRNumber(%q) = %q, want rejection", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Fatalf("normCDRNumber(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
}

func TestParseCDRTimeFormats(t *testing.T) {
	full, ok := parseCDRTime("20261001153045")
	if !ok || !full.Equal(time.Date(2026, 10, 1, 15, 30, 45, 0, Loc)) {
		t.Fatalf("full: %v %v", full, ok)
	}
	dateOnly, ok := parseCDRTime("20261001")
	if !ok || !dateOnly.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, Loc)) {
		t.Fatalf("date-only: %v %v", dateOnly, ok)
	}
	iso, ok := parseCDRTime("2026-10-01 15:30:45")
	if !ok || !iso.Equal(time.Date(2026, 10, 1, 15, 30, 45, 0, Loc)) {
		t.Fatalf("iso: %v %v", iso, ok)
	}
	if _, ok := parseCDRTime("not-a-date"); ok {
		t.Fatal("garbage must be rejected")
	}
}

func TestCDRDialableParsesForEveryOperatorFamily(t *testing.T) {
	// Регрессия: все 12 кодов кейса должны успешно разбираться phone.Parse (иначе Callee не
	// проходит phone.Parse в enrich.Enrich, и весь вызов падает ошибкой валидации — так было
	// найдено живым прогоном cmd/cdrflag на официальном датасете: сперва ~34% вызовов отваливались
	// на кодах Альфы/Bell-ka (не начинаются с 3/4/8/9 — мимо эвристики российского номера), а после
	// первого исправления ещё ~2% — на коде Барбетты 810 (phone.Parse отдельно срезает ведущие
	// "810" как префикс международного набора, не видя, что это целый номер). Суффиксы — не
	// только "1234567": с ним "810"+"1234567" после среза "810" превращается в "1234567",
	// начинающееся с '1' — то есть в НАСТОЯЩИЙ код NANP, и phone.Parse ошибочно, но "успешно"
	// разбирал бы его как североамериканский номер, маскируя баг. Несколько разных суффизов,
	// включая такие, что не начинаются с 1/7/реальных кодов стран, ловят это по-честному.
	suffixes := []string{"1234567", "0000000", "9999999", "5550123", "0049333", "7654321"}
	for prefix := range cdrValidPrefixes {
		for _, suffix := range suffixes {
			number := prefix + suffix
			dialable := cdrDialable(number)
			if _, err := phone.Parse(dialable); err != nil {
				t.Fatalf("phone.Parse(%q) [код %s, суффикс %s]: %v", dialable, prefix, suffix, err)
			}
			if got := CDRBareNumber(dialable); got != number {
				t.Fatalf("round-trip %q → %q → %q, want %q", number, dialable, got, number)
			}
		}
	}
}

func TestCDRDialableBarbetta810IsWrapped(t *testing.T) {
	// Явная регрессия на сам баг: бывший "безопасный по первой цифре" вариант отдавал "810..."
	// как есть, и phone.Parse срезал "810" как префикс набора за рубеж.
	dialable := cdrDialable("8100049333")
	if !strings.HasPrefix(dialable, "+49") {
		t.Fatalf("810 must be wrapped, got %q", dialable)
	}
	n, err := phone.Parse(dialable)
	if err != nil || n.National != "8100049333" {
		t.Fatalf("parse(%q) = %+v, %v", dialable, n, err)
	}
}

func TestCDRBareNumberOnShortInput(t *testing.T) {
	if got := CDRBareNumber("8991234567"); got != "8991234567" {
		t.Fatalf("already-bare input must pass through: %q", got)
	}
}

func TestIsCDRPath(t *testing.T) {
	if !IsCDRPath("CDR_000001_20261001000000.cdr") || IsCDRPath("calls.csv") {
		t.Fatal("extension detection")
	}
}
