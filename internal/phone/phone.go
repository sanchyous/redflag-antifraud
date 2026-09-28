// Package phone — нормализация телефонных номеров к E.164, разбор масок вида
// "+7 495 ***-**-12", определение страны по префиксу и безопасные представления
// номера для логов (маска, HMAC-идентификатор). Сырые номера в журналы не попадают.
package phone

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// Ошибки разбора.
var (
	ErrEmpty   = errors.New("phone: empty")
	ErrInvalid = errors.New("phone: invalid number")
	ErrTooLong = errors.New("phone: too many digits")
)

const (
	maxDigits   = 15 // E.164
	minDigits   = 7  // короче — считаем либо коротким сервисным, либо мусором
	maxShortLen = 6
)

// Number — разобранный номер. Digits хранит цифры E.164 без "+"; в масках
// скрытые позиции сохранены как '*'.
type Number struct {
	Digits   string // цифры E.164, у короткого номера — как введены
	CC       string // код страны, "" у короткого
	ISO      string // ISO 3166-1 alpha-2 ("NANP" для +1), "" у короткого
	National string // Digits без кода страны
	Short    bool   // короткий/сервисный номер (112, 103, 900 ...)
	Masked   bool   // содержит '*'
}

// Parse разбирает номер в любом из распространённых форматов:
// "+7 (916) 123-45-67", "89161234567", "9161234567", "8 10 49 30 ...", "0049...",
// "+7 495 ***-**-12" (маска), "112". Номер без "+" длиной 8+ цифр, не подошедший под
// российские шаблоны, трактуется как E.164 без плюса.
func Parse(raw string) (Number, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Number{}, ErrEmpty
	}
	hasPlus := s[0] == '+'
	if hasPlus {
		s = s[1:]
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r == '*':
			b.WriteRune(r)
		case r == ' ', r == '-', r == '(', r == ')', r == '.', r == ' ':
		default:
			return Number{}, ErrInvalid
		}
	}
	c := b.String()
	if c == "" {
		return Number{}, ErrInvalid
	}
	masked := strings.Contains(c, "*")

	if !hasPlus {
		if len(c) <= maxShortLen {
			if masked {
				return Number{}, ErrInvalid
			}
			return Number{Digits: c, Short: true}, nil
		}
		switch {
		case strings.HasPrefix(c, "810"):
			c = c[3:]
		case strings.HasPrefix(c, "00"):
			c = c[2:]
		case len(c) == 11 && c[0] == '8':
			c = "7" + c[1:]
		case len(c) == 10 && strings.IndexByte("3489", c[0]) >= 0:
			c = "7" + c
		}
	}
	if len(c) > maxDigits {
		return Number{}, ErrTooLong
	}
	if len(c) < minDigits {
		return Number{}, ErrInvalid
	}
	cc, iso, ok := lookupCountry(c)
	if !ok {
		return Number{}, ErrInvalid
	}
	return Number{
		Digits:   c,
		CC:       cc,
		ISO:      iso,
		National: c[len(cc):],
		Masked:   masked,
	}, nil
}

// E164 возвращает "+<digits>". Для короткого номера — как есть.
func (n Number) E164() string {
	if n.Short {
		return n.Digits
	}
	return "+" + n.Digits
}

// Complete — номер известен полностью (не маска и не пустой).
func (n Number) Complete() bool { return n.Digits != "" && !n.Masked }

// IsRU — российский номер (+7 с кодами 3/4/8/9).
func (n Number) IsRU() bool { return n.ISO == "RU" }

// Prefix возвращает первые k цифр национальной части, если они известны (не '*').
func (n Number) Prefix(k int) (string, bool) {
	if n.Short || k <= 0 || len(n.National) < k {
		return "", false
	}
	p := n.National[:k]
	if strings.Contains(p, "*") {
		return "", false
	}
	return p, true
}

// Mask — безопасное для логов представление: видны код страны, первые 3 цифры
// национальной части и последние 2 цифры. "+79161234583" → "+7 916 ***-**-83".
func (n Number) Mask() string {
	if n.Short {
		return n.Digits
	}
	nat := n.National
	if len(nat) < 6 {
		return "+" + n.CC + " " + strings.Repeat("*", len(nat))
	}
	head, tail := nat[:3], nat[len(nat)-2:]
	mid := len(nat) - 5
	var body string
	if n.CC == "7" && len(nat) == 10 {
		body = "***-**-" + tail
	} else {
		body = strings.Repeat("*", mid) + "-" + tail
	}
	// Если сам вход уже был маской, '*' в head/tail остаются как есть.
	return "+" + n.CC + " " + head + " " + body
}

// ID — стабильный псевдоним номера для связывания записей без хранения самого номера:
// hex(HMAC-SHA256(key, E164))[:32]. Для маскированных и коротких номеров ok=false.
func (n Number) ID(key []byte) (id string, ok bool) {
	if n.Short || n.Masked || n.Digits == "" {
		return "", false
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(n.E164()))
	return hex.EncodeToString(m.Sum(nil))[:32], true
}

// Ключи номеров: компактный uint64 для карт и окон без строк в горячем пути.
//
//	полный номер:      значение цифр (< 10^15, старшие биты нули)
//	короткий номер:    1<<62 | длина<<50 | значение
//	маскированный:     1<<63 | 63-битный FNV-1a от цифр и '*'
const (
	keyShort  = uint64(1) << 62
	keyMasked = uint64(1) << 63
)

// Key возвращает стабильный uint64-идентификатор номера. Разные записи одного и того же
// номера ("8916…" и "+7 916…") дают один ключ. Маскированные номера получают ключ
// по маске: две одинаковые маски неразличимы, это ограничение данных.
func (n Number) Key() uint64 {
	switch {
	case n.Short:
		var v uint64
		for i := 0; i < len(n.Digits); i++ {
			v = v*10 + uint64(n.Digits[i]-'0')
		}
		return keyShort | uint64(len(n.Digits))<<50 | v
	case n.Masked:
		h := uint64(14695981039346656037)
		for i := 0; i < len(n.Digits); i++ {
			h ^= uint64(n.Digits[i])
			h *= 1099511628211
		}
		return keyMasked | h>>1
	default:
		var v uint64
		for i := 0; i < len(n.Digits); i++ {
			v = v*10 + uint64(n.Digits[i]-'0')
		}
		return v
	}
}

// lookupCountry определяет код страны и ISO по началу E.164-цифр.
func lookupCountry(d string) (cc, iso string, ok bool) {
	switch d[0] {
	case '1':
		return "1", "NANP", true
	case '7':
		if len(d) < 2 {
			return "", "", false
		}
		switch d[1] {
		case '3', '4', '8', '9':
			return "7", "RU", true
		case '6', '7':
			return "7", "KZ", true
		}
		return "", "", false
	}
	if len(d) >= 2 {
		if v, ok := codes2[d[:2]]; ok {
			return d[:2], v, true
		}
	}
	if len(d) >= 3 {
		if v, ok := codes3[d[:3]]; ok {
			return d[:3], v, true
		}
	}
	return "", "", false
}
