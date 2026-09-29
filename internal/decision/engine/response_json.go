package engine

import (
	"math"
	"strconv"
	"unicode/utf8"
)

// AppendJSON дописывает JSON ответа в b без рефлексии и лишних аллокаций. Формат тот же, что даёт encoding/json
// для структуры Response (имена полей, порядок, omitempty): проверяется тестами сравнением с json.Marshal.
// Отличие одно: символы <, > и & не экранируются (они безопасны для JSON, а ответ отдаётся как application/json).
//
// Зачем: при десятках тысяч запросов в секунду кодирование ответа через reflection занимало больше времени, чем сам
// скоринг вызова (по профилю ~17% против ~14%).
func (r *Response) AppendJSON(b []byte) []byte {
	b = append(b, `{"call_id":`...)
	b = appendString(b, r.CallID)
	b = append(b, `,"decision":`...)
	b = appendString(b, r.Decision)
	b = append(b, `,"score":`...)
	b = appendFloat(b, r.Score)
	b = append(b, `,"summary":`...)
	b = appendString(b, r.Summary)
	b = append(b, `,"reasons":[`...)
	for i := range r.Reasons {
		if i > 0 {
			b = append(b, ',')
		}
		x := &r.Reasons[i]
		b = append(b, `{"factor":`...)
		b = appendString(b, x.Factor)
		b = append(b, `,"value":`...)
		b = appendFloat(b, x.Value)
		b = append(b, `,"contribution":`...)
		b = appendFloat(b, x.Contribution)
		b = append(b, `,"effect":`...)
		b = appendString(b, x.Effect)
		b = append(b, `,"text":`...)
		b = appendString(b, x.Text)
		b = append(b, '}')
	}
	b = append(b, ']')
	if len(r.Signals) > 0 {
		b = append(b, `,"signals":[`...)
		for i, s := range r.Signals {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendString(b, s)
		}
		b = append(b, ']')
	}
	b = append(b, `,"caller":`...)
	b = r.Caller.appendJSON(b)
	b = append(b, `,"callee":`...)
	b = r.Callee.appendJSON(b)
	if r.SafeClass != "" {
		b = append(b, `,"safe_class":`...)
		b = appendString(b, r.SafeClass)
	}
	if r.BlockSuppressed {
		b = append(b, `,"block_suppressed":true`...)
	}
	if r.RuleFloor {
		b = append(b, `,"rule_floor":true`...)
	}
	if r.Duplicate {
		b = append(b, `,"duplicate":true`...)
	}
	b = append(b, `,"stage":`...)
	b = appendString(b, r.Stage)
	b = append(b, `,"model_version":`...)
	b = appendString(b, r.ModelVersion)
	if r.NumplanVersion != "" {
		b = append(b, `,"numplan_version":`...)
		b = appendString(b, r.NumplanVersion)
	}
	b = append(b, `,"latency_us":`...)
	b = strconv.AppendInt(b, r.LatencyUS, 10)
	return append(b, '}')
}

func (p *Party) appendJSON(b []byte) []byte {
	b = append(b, `{"masked":`...)
	b = appendString(b, p.Masked)
	if p.Country != "" {
		b = append(b, `,"country":`...)
		b = appendString(b, p.Country)
	}
	if p.Region != "" {
		b = append(b, `,"region":`...)
		b = appendString(b, p.Region)
	}
	if p.Operator != "" {
		b = append(b, `,"operator":`...)
		b = appendString(b, p.Operator)
	}
	return append(b, '}')
}

// appendFloat пишет число так же, как encoding/json: короткая десятичная запись, экспонента для очень малых и больших
// значений. Нечисловые значения (NaN, Inf) в JSON недопустимы и заменяются нулём — скоринг их не порождает.
func appendFloat(b []byte, f float64) []byte {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return append(b, '0')
	}
	abs := math.Abs(f)
	format := byte('f')
	if abs != 0 && (abs < 1e-6 || abs >= 1e21) {
		format = 'e'
	}
	b = strconv.AppendFloat(b, f, format, -1, 64)
	if format == 'e' { // e-09 → e-9, как в encoding/json
		if n := len(b); n >= 4 && b[n-4] == 'e' && b[n-3] == '-' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
	}
	return b
}

const hexDigits = "0123456789abcdef"

// appendString пишет строку JSON: экранирует кавычку, обратную косую, управляющие символы, U+2028 и U+2029;
// некорректный UTF-8 заменяется на U+FFFD (как в encoding/json). Кириллица и прочий UTF-8 остаются как есть.
func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			b = append(b, s[start:i]...)
			switch c {
			case '"', '\\':
				b = append(b, '\\', c)
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			default:
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b = append(b, s[start:i]...)
			b = append(b, `�`...)
			i += size
			start = i
			continue
		}
		if r == ' ' || r == ' ' {
			b = append(b, s[start:i]...)
			b = append(b, '\\', 'u', '2', '0', '2', hexDigits[r&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}

// AppendString дописывает строку в JSON-виде (для сборки составных ответов, например пакетного).
func AppendString(b []byte, s string) []byte { return appendString(b, s) }
