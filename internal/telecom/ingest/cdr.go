package ingest

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/telecom/callrec"
)

// cdrValidPrefixes — трёхзначные коды операторов/городов из материалов кейса (поле «номер» —
// код + 7 цифр). Список приходит с кейсом, а не из справочника Россвязи: формат датасета
// специально урезан до того, что видно в сигнализации коммутатора.
var cdrValidPrefixes = map[string]bool{
	"025": true, "026": true, "027": true, // Альфа
	"210": true, "214": true, "200": true, // Bell-ka
	"842": true, "499": true, "892": true, // городские
	"899": true, "810": true, "834": true, // Барбетта
}

// normCDRNumber нормализует номер из CDR: как есть — 10 цифр с известным кодом; иначе пробует
// снять ведущий код страны (+7/7/8 — кейс явно предупреждает про «коды стран» в мусорных строках).
// Проверка «как есть» идёт первой: у части валидных кодов (899, 810, 834) первая цифра — «8»,
// и снятие ведущей цифры испортило бы уже корректный номер.
func normCDRNumber(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	s = strings.TrimPrefix(s, "+7")
	if len(s) == 10 && isDigits(s) && cdrValidPrefixes[s[:3]] {
		return s, true
	}
	if len(s) == 11 && isDigits(s) && (s[0] == '7' || s[0] == '8') {
		if cand := s[1:]; cdrValidPrefixes[cand[:3]] {
			return cand, true
		}
	}
	if len(s) == 12 && isDigits(s) && strings.HasPrefix(s, "78") {
		if cand := s[2:]; cdrValidPrefixes[cand[:3]] {
			return cand, true
		}
	}
	return "", false
}

// cdrBarePassthrough — коды кейса, которые phone.Parse и так примет как российский
// национальный номер (10 цифр, начинается с 3/4/8/9) без искажений. 810 из этого списка
// сознательно исключён: phone.Parse отдельно распознаёт ведущие "810" как префикс
// международного набора (реальный российский IDD-код) и отрезает их безусловно, что для
// кода Барбетты «810» ломает номер — поэтому 810 тоже оборачивается, как Альфа и Bell-ka.
var cdrBarePassthrough = map[string]bool{
	"842": true, "499": true, "892": true, // городские
	"899": true, "834": true, // Барбетта (без 810 — см. выше)
}

// cdrDialable превращает канонический 10-значный номер кейса в строку, которую примет
// phone.Parse. Коды Альфы (025-027), Bell-ka (210, 214, 200) и Барбетты-810 не попадают ни под
// одну реальную схему ITU-T и совпадают с несвязанными эвристиками phone.Parse — это вымышленная
// нумерация кейса, не настоящий план нумерации. Чтобы такие номера не падали с ErrInvalid (а
// значит, не ломали скоринг вызова целиком), они оборачиваются кодом страны +49 (сам по себе не
// используется нигде в проверках ForeignIngress/Spoof: те смотрят на SrcCountry/ConnType из
// сигнализации, а не на ISO разобранного номера) — страна тут условность, важна только успешная
// и обратимая (phone.Number.Key детерминирован по цифрам) разборка.
func cdrDialable(number string) string {
	if len(number) == 10 && cdrBarePassthrough[number[:3]] {
		return number
	}
	return "+49" + number
}

// cdrBareNumber восстанавливает канонический 10-значный номер кейса из того, что положили в
// callrec.Call (см. cdrDialable) — последние 10 цифр строки, что бы к ним ни было приписано.
func CDRBareNumber(dialable string) string {
	if len(dialable) <= 10 {
		return dialable
	}
	return dialable[len(dialable)-10:]
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func normCDRImsi(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 15 && isDigits(s) {
		return s
	}
	return ""
}

// parseCDRTime разбирает время CDR: полный yyyymmddhh24miss, укороченный yyyymmdd (без времени —
// считается 00:00:00) и запасной формат "yyyy-mm-dd hh:mm:ss" — кейс явно предупреждает, что
// часть строк «неверные даты» вперемешку с нестандартным форматом, а не только битые.
func parseCDRTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	switch len(s) {
	case 14:
		if t, err := time.ParseInLocation("20060102150405", s, Loc); err == nil {
			return t, true
		}
	case 8:
		if t, err := time.ParseInLocation("20060102", s, Loc); err == nil {
			return t, true
		}
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, Loc); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// ReadCDR читает выгрузку коммутатора в фиксированном позиционном формате кейса:
// тип;IMSI;номер A;номер B;начало yyyymmddhh24miss;длительность;[номер C при переадресации].
// Без заголовка, разделитель — ';'. Строки с неизвестным типом, неразбираемыми номерами,
// нечитаемой датой или отрицательной/абсурдной длительностью пропускаются как RowError —
// кейс прямо предупреждает про мусорные строки (лишние поля, коды стран, неверные даты) и
// оставляет на усмотрение решающего, как их обрабатывать.
func ReadCDR(r io.Reader) (*Result, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	res := &Result{}
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, ";")
		if len(parts) < 6 {
			res.Errors = append(res.Errors, RowError{ln, errors.New("слишком мало полей")})
			continue
		}
		typ := strings.TrimSpace(parts[0])
		dir, ok := callrec.ParseDirection(typ)
		if !ok || dir == callrec.DirUnknown {
			res.Errors = append(res.Errors, RowError{ln, errors.New("неизвестный тип записи " + typ)})
			continue
		}
		a, aok := normCDRNumber(parts[2])
		b, bok := normCDRNumber(parts[3])
		if !aok || !bok {
			res.Errors = append(res.Errors, RowError{ln, errors.New("номер не разобран")})
			continue
		}
		ts, tok := parseCDRTime(parts[4])
		if !tok {
			res.Errors = append(res.Errors, RowError{ln, errors.New("дата не разобрана: " + parts[4])})
			continue
		}
		dur, err := strconv.Atoi(strings.TrimSpace(parts[5]))
		if err != nil || dur < 0 || dur > 24*3600 {
			res.Errors = append(res.Errors, RowError{ln, errors.New("длительность " + parts[5])})
			continue
		}
		rec := Record{Line: ln}
		c := &rec.Call
		c.CallID = "cdr-" + strconv.Itoa(ln)
		c.StartedAt = ts
		c.DurationSec = dur
		c.IMSI = normCDRImsi(parts[1])
		switch dir {
		case callrec.DirIncoming: // «входящий к A» — фактически звонил B
			c.Caller, c.Callee = cdrDialable(b), cdrDialable(a)
		default: // исходящий и переадресация: звонил A
			c.Caller, c.Callee = cdrDialable(a), cdrDialable(b)
		}
		c.Direction = dir
		if dir == callrec.DirForwarded {
			if len(parts) > 6 {
				if cn, ok := normCDRNumber(parts[6]); ok {
					c.ForwardTo = cdrDialable(cn)
				}
			}
			if c.ForwardTo == "" {
				res.Errors = append(res.Errors, RowError{ln, errors.New("переадресация без номера C")})
				continue
			}
		}
		res.Records = append(res.Records, rec)
	}
	return res, sc.Err()
}

// ReadCDRFile открывает и читает один файл CDR_*.cdr.
func ReadCDRFile(path string) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadCDR(f)
}

// IsCDRPath — расширение .cdr (формат кейса), в отличие от .csv/.jsonl в ReadFile.
func IsCDRPath(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".cdr")
}
