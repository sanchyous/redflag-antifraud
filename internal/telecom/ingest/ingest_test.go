package ingest

import (
	"strings"
	"testing"
	"time"
)

func TestCSVWithSynonymsAndSemicolons(t *testing.T) {
	src := "\ufeffA-number;B-number;Start Time;Billsec;Status;Country;Operator;Fraud\n" +
		"+7 495 123-45-67;+7 916 765-43-21;2026-10-14 11:42:00;6;ANSWERED;de;MTS;1\n" +
		"+7 916 111-22-33;+7 495 999-88-77;2026-10-14 11:43:10;0;NO ANSWER;;;0\n"
	res, err := ReadCSV(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 || len(res.Errors) != 0 {
		t.Fatalf("%+v", res)
	}
	a := res.Records[0]
	if a.Call.Caller != "+7 495 123-45-67" || a.Call.DurationSec != 6 || a.Call.SrcCountry != "DE" || a.Call.SrcOperator != "MTS" {
		t.Fatalf("call = %+v", a.Call)
	}
	if a.Call.Answered == nil || !*a.Call.Answered || a.Label == nil || !*a.Label {
		t.Fatalf("answered/label: %+v", a)
	}
	if want := time.Date(2026, 10, 14, 11, 42, 0, 0, Loc); !a.Call.StartedAt.Equal(want) {
		t.Fatalf("time = %v", a.Call.StartedAt)
	}
	b := res.Records[1]
	if b.Call.Answered == nil || *b.Call.Answered || b.Label == nil || *b.Label {
		t.Fatalf("second record: %+v", b)
	}
	if a.Call.CallID != "row-2" || b.Call.CallID != "row-3" {
		t.Fatalf("generated ids: %s %s", a.Call.CallID, b.Call.CallID)
	}
}

func TestCSVDelimiters(t *testing.T) {
	for name, sep := range map[string]string{"comma": ",", "tab": "\t", "pipe": "|"} {
		src := "caller" + sep + "callee" + sep + "duration\n+79161234567" + sep + "+74957654321" + sep + "10\n"
		res, err := ReadCSV(strings.NewReader(src))
		if err != nil || len(res.Records) != 1 || res.Records[0].Call.DurationSec != 10 {
			t.Fatalf("%s: %+v %v", name, res, err)
		}
	}
}

func TestCSVMissingRequiredColumns(t *testing.T) {
	if _, err := ReadCSV(strings.NewReader("foo,bar\n1,2\n")); err == nil || !strings.Contains(err.Error(), "caller") {
		t.Fatalf("err = %v", err)
	}
	if _, err := ReadCSV(strings.NewReader("")); err == nil {
		t.Fatal("empty file must fail")
	}
}

func TestBadRowsAreReportedNotFatal(t *testing.T) {
	src := "caller,callee,duration,start\n" +
		"+79161234567,+74957654321,10,2026-10-14 11:00:00\n" +
		"+79161234567,,10,2026-10-14 11:00:00\n" + // нет callee
		"+79161234567,+74957654321,abc,2026-10-14 11:00:00\n" + // плохая длительность
		"+79161234567,+74957654321,10,вчера\n" + // плохое время
		"+79161234567,+74957654321,12,2026-10-14 11:05:00\n"
	res, err := ReadCSV(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 || len(res.Errors) != 3 {
		t.Fatalf("records=%d errors=%v", len(res.Records), res.Errors)
	}
	if res.Errors[0].Line != 3 || !strings.Contains(res.Errors[0].Error(), "строка 3") {
		t.Fatalf("error line info: %v", res.Errors[0])
	}
}

func TestJSONL(t *testing.T) {
	src := `{"call_id":"c1","from":"+7 495 123-45-67","to":"+7 916 765-43-21","start_time":1760427720,"duration":"00:00:06","answered":true,"label":"fraud","src_country":"de"}` + "\n\n" +
		`{"caller":"+79161112233","callee":"+74959998877","timestamp":1760427790000,"duration_sec":0,"answered":0}` + "\n" +
		`{не json}` + "\n"
	res, err := ReadJSONL(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 || len(res.Errors) != 1 || res.Errors[0].Line != 4 {
		t.Fatalf("%+v", res)
	}
	a := res.Records[0]
	if a.Call.CallID != "c1" || a.Call.DurationSec != 6 || a.Label == nil || !*a.Label || a.Call.SrcCountry != "DE" {
		t.Fatalf("a = %+v", a)
	}
	if a.Call.StartedAt.Unix() != 1760427720 {
		t.Fatalf("unix seconds: %v", a.Call.StartedAt)
	}
	if res.Records[1].Call.StartedAt.UnixMilli() != 1760427790000 {
		t.Fatalf("unix millis: %v", res.Records[1].Call.StartedAt)
	}
}

func TestParseTimeFormats(t *testing.T) {
	want := time.Date(2026, 10, 14, 11, 42, 5, 0, Loc)
	for _, s := range []string{"2026-10-14 11:42:05", "2026-10-14T11:42:05", "14.10.2026 11:42:05", "2026-10-14T11:42:05+03:00", "2026-10-14T08:42:05Z"} {
		got, err := ParseTime(s)
		if err != nil || !got.Equal(want) {
			t.Fatalf("%q → %v, %v", s, got, err)
		}
	}
	if _, err := ParseTime("не время"); err == nil {
		t.Fatal("garbage must fail")
	}
}

func TestDurationForms(t *testing.T) {
	cases := map[string]int{"6": 6, "6.4": 6, "6,6": 7, "01:02": 62, "1:01:01": 3661, "0": 0}
	for in, want := range cases {
		if got, err := parseDuration(in); err != nil || got != want {
			t.Fatalf("%q → %d, %v (want %d)", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "-5", "NaN", "a:b"} {
		if _, err := parseDuration(bad); err == nil {
			t.Fatalf("%q must fail", bad)
		}
	}
}

func TestAnsweredAndConnNormalization(t *testing.T) {
	if v, ok := parseAnswered("BUSY"); !ok || v {
		t.Fatal("busy = not answered")
	}
	if _, ok := parseAnswered("что-то"); ok {
		t.Fatal("unknown status must be undetermined, not guessed")
	}
	for in, want := range map[string]string{"Mobile": "mobile", "международный": "international", "SIP trunk": "voip", "городской": "fixed", "": "", "космос": ""} {
		if got := normConn(in); got != want {
			t.Fatalf("normConn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnansweredWithDurationIsNormalized(t *testing.T) {
	res, _ := ReadCSV(strings.NewReader("caller,callee,duration,answered\n+79161234567,+74957654321,25,no\n"))
	c := res.Records[0].Call
	if c.DurationSec != 0 || c.Answered == nil || *c.Answered {
		t.Fatalf("%+v", c)
	}
}

func TestReadFileByExtension(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := dir + "/" + name
		if err := osWrite(p, body); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if r, err := ReadFile(write("a.csv", "caller,callee,duration\n+79161234567,+74957654321,5\n")); err != nil || len(r.Records) != 1 {
		t.Fatalf("csv: %v", err)
	}
	if r, err := ReadFile(write("a.jsonl", `{"caller":"+79161234567","callee":"+74957654321","duration":5}`)); err != nil || len(r.Records) != 1 {
		t.Fatalf("jsonl: %v", err)
	}
	if _, err := ReadFile(write("a.xlsx", "x")); err == nil {
		t.Fatal("unknown extension must fail")
	}
	if _, err := ReadFile(dir + "/missing.csv"); err == nil {
		t.Fatal("missing file must fail")
	}
}
