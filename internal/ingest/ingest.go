// Package ingest читает выгрузки вызовов (CSV и JSONL) с гибким сопоставлением колонок. Формат закрытого
// набора заранее неизвестен, поэтому имена колонок приводятся к нормальной форме (регистр, пробелы,
// подчёркивания и дефисы не важны) и сопоставляются со списком синонимов: caller / from / src / a_number,
// callee / to / dst / b_number, started_at / start_time / timestamp и так далее.
package ingest

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/callrec"
)

// Record — вызов с необязательной меткой (мошеннический или нет).
type Record struct {
	Call  callrec.Call
	Label *bool
	Line  int // номер строки в источнике (для сообщений об ошибках)
}

// RowError — ошибка разбора одной строки; остальные строки читаются дальше.
type RowError struct {
	Line int
	Err  error
}

func (e RowError) Error() string { return fmt.Sprintf("строка %d: %v", e.Line, e.Err) }

// Result — прочитанные записи и ошибки по отдельным строкам.
type Result struct {
	Records []Record
	Errors  []RowError
}

// Loc — часовой пояс для времён без указания зоны (по умолчанию Москва, как в ТЗ-примере).
var Loc = time.FixedZone("MSK", 3*3600)

var aliases = map[string][]string{
	"call_id":       {"callid", "id", "uuid", "cdrid", "recordid", "callref", "sessionid"},
	"caller":        {"caller", "from", "src", "source", "anumber", "calling", "callingnumber", "cli", "msisdna", "origin", "numbera", "srcnumber", "fromnumber"},
	"callee":        {"callee", "to", "dst", "destination", "bnumber", "called", "callednumber", "msisdnb", "numberb", "dstnumber", "tonumber"},
	"started_at":    {"startedat", "start", "starttime", "timestamp", "time", "datetime", "calldate", "date", "ts", "begin", "setuptime", "calltime"},
	"duration_sec":  {"durationsec", "duration", "billsec", "seconds", "length", "talktime", "calldurationsec", "durationseconds"},
	"answered":      {"answered", "isanswered", "connected", "status", "disposition", "callstatus", "result"},
	"conn_type":     {"conntype", "calltype", "type", "connection", "connectiontype", "networktype"},
	"src_country":   {"srccountry", "country", "origincountry", "sourcecountry", "countrysrc", "fromcountry"},
	"src_operator":  {"srcoperator", "operator", "sourceoperator", "carrier", "operatorsrc", "srcnetwork"},
	"subscriber_id": {"subscriberid", "subscriber", "abonent", "abonentid", "customerid", "userid", "accountid"},
	"label":         {"label", "isfraud", "fraud", "target", "class", "y", "isspam", "spam", "scam"},
}

func norm(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if r == '_' || r == '-' || r == ' ' || r == '.' {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimPrefix(b.String(), "\ufeff")
}

// mapping сопоставляет каноническое имя поля с индексом колонки.
func mapping(header []string) map[string]int {
	idx := map[string]int{}
	for i, h := range header {
		idx[norm(h)] = i
	}
	out := map[string]int{}
	for field, names := range aliases {
		for _, n := range names {
			if i, ok := idx[n]; ok {
				out[field] = i
				break
			}
		}
	}
	return out
}

// ReadCSV читает CSV с заголовком; разделитель определяется автоматически (`,`, `;`, `\t`).
func ReadCSV(r io.Reader) (*Result, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	if b, err := br.Peek(3); err == nil && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		_, _ = br.Discard(3)
	}
	first, err := br.Peek(4096)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return nil, err
	}
	line := string(first)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	cr := csv.NewReader(br)
	cr.Comma = detectComma(line)
	cr.LazyQuotes = true
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("ingest: пустой файл или нет заголовка: %w", err)
	}
	m := mapping(header)
	if err := checkRequired(m, header); err != nil {
		return nil, err
	}
	res := &Result{}
	for ln := 2; ; ln++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			res.Errors = append(res.Errors, RowError{ln, err})
			continue
		}
		get := func(field string) string {
			if i, ok := m[field]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		add(res, ln, get)
	}
	return res, nil
}

func detectComma(header string) rune {
	best, n := ',', strings.Count(header, ",")
	for _, c := range []rune{';', '\t', '|'} {
		if k := strings.Count(header, string(c)); k > n {
			best, n = c, k
		}
	}
	return best
}

func checkRequired(m map[string]int, header []string) error {
	var missing []string
	for _, f := range []string{"caller", "callee", "duration_sec"} {
		if _, ok := m[f]; !ok {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("ingest: не найдены колонки %v среди %v", missing, header)
	}
	return nil
}

// ReadJSONL читает по объекту JSON в строке (имена полей — те же синонимы, значения — числа, строки, булевы).
func ReadJSONL(r io.Reader) (*Result, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	res := &Result{}
	ln := 0
	for sc.Scan() {
		ln++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(text), &obj); err != nil {
			res.Errors = append(res.Errors, RowError{ln, err})
			continue
		}
		byNorm := map[string]string{}
		for k, v := range obj {
			byNorm[norm(k)] = scalar(v)
		}
		get := func(field string) string {
			for _, n := range aliases[field] {
				if v, ok := byNorm[n]; ok {
					return v
				}
			}
			return ""
		}
		add(res, ln, get)
	}
	return res, sc.Err()
}

func scalar(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(x)
	case bool:
		return strconv.FormatBool(x)
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1e15 {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

// ReadFile читает файл по расширению: .csv, .tsv, .jsonl, .ndjson, .json (как JSONL).
func ReadFile(path string) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	switch strings.ToLower(filepath.Ext(path)) {
	case ".csv", ".tsv", ".txt":
		return ReadCSV(f)
	case ".jsonl", ".ndjson", ".json":
		return ReadJSONL(f)
	}
	return nil, fmt.Errorf("ingest: неизвестное расширение %q (нужны .csv, .jsonl)", filepath.Ext(path))
}

func add(res *Result, ln int, get func(string) string) {
	rec := Record{Line: ln}
	c := &rec.Call
	c.CallID = get("call_id")
	if c.CallID == "" {
		c.CallID = "row-" + strconv.Itoa(ln)
	}
	c.Caller, c.Callee = get("caller"), get("callee")
	if c.Callee == "" {
		res.Errors = append(res.Errors, RowError{ln, errors.New("пустой callee")})
		return
	}
	d, err := parseDuration(get("duration_sec"))
	if err != nil {
		res.Errors = append(res.Errors, RowError{ln, err})
		return
	}
	c.DurationSec = d
	if s := get("started_at"); s != "" {
		t, err := ParseTime(s)
		if err != nil {
			res.Errors = append(res.Errors, RowError{ln, err})
			return
		}
		c.StartedAt = t
	}
	if s := get("answered"); s != "" {
		if v, ok := parseAnswered(s); ok {
			c.Answered = &v
		}
	}
	c.ConnType = normConn(get("conn_type"))
	c.SrcCountry = strings.ToUpper(get("src_country"))
	if len(c.SrcCountry) != 2 {
		c.SrcCountry = ""
	}
	c.SrcOperator = get("src_operator")
	c.SubscriberID = get("subscriber_id")
	if s := get("label"); s != "" {
		if v, ok := parseLabel(s); ok {
			rec.Label = &v
		}
	}
	// Противоречие «не отвечен, но есть длительность» встречается в выгрузках (длительность
	// звонка с гудками): считаем вызов неотвеченным с нулевой длительностью.
	if c.Answered != nil && !*c.Answered && c.DurationSec > 0 {
		c.DurationSec = 0
	}
	res.Records = append(res.Records, rec)
}

func parseDuration(s string) (int, error) {
	if s == "" {
		return 0, errors.New("пустая длительность")
	}
	if strings.Contains(s, ":") { // hh:mm:ss или mm:ss
		parts := strings.Split(s, ":")
		total := 0
		for _, p := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || n < 0 {
				return 0, fmt.Errorf("длительность %q", s)
			}
			total = total*60 + n
		}
		return total, nil
	}
	f, err := strconv.ParseFloat(strings.ReplaceAll(s, ",", "."), 64)
	if err != nil || f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("длительность %q", s)
	}
	return int(math.Round(f)), nil
}

// ParseTime разбирает время: RFC3339, "2006-01-02 15:04:05" (зона Loc), "02.01.2006 15:04:05", unix-секунды и миллисекунды.
func ParseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04:05.000", "02.01.2006 15:04:05", "02.01.2006 15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, Loc); err == nil {
			return t, nil
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
		switch {
		case n > 1e14: // микросекунды
			return time.UnixMicro(n), nil
		case n > 1e11: // миллисекунды
			return time.UnixMilli(n), nil
		}
		return time.Unix(n, 0), nil
	}
	return time.Time{}, fmt.Errorf("время %q не распознано", s)
}

func parseAnswered(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "да", "answered", "answer", "connected", "success", "completed", "ok":
		return true, true
	case "0", "false", "no", "n", "нет", "no answer", "noanswer", "unanswered", "busy", "failed", "cancel", "cancelled", "canceled", "rejected", "missed":
		return false, true
	}
	return false, false
}

func parseLabel(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "fraud", "spam", "scam", "bad", "malicious", "мошенник", "да":
		return true, true
	case "0", "false", "no", "n", "legit", "normal", "ok", "good", "benign", "нет":
		return false, true
	}
	return false, false
}

func normConn(s string) string {
	if v, ok := callrec.ParseConnType(s); ok {
		if v == callrec.ConnUnknown {
			return "" // строку "unknown" валидатор ядра не принимает: неизвестный тип — пустой
		}
		return v.String()
	}
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "inter") || strings.Contains(l, "межд") || strings.Contains(l, "transit"):
		return "international"
	case strings.Contains(l, "mob") || strings.Contains(l, "сот"):
		return "mobile"
	case strings.Contains(l, "voip") || strings.Contains(l, "sip"):
		return "voip"
	case strings.Contains(l, "fix") || strings.Contains(l, "city") || strings.Contains(l, "гор"):
		return "fixed"
	}
	return "" // неизвестный тип соединения не должен ронять всю строку
}
