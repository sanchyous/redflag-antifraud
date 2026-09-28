// Package protect — защитный слой: вызовы, которые нельзя блокировать никогда.
//
// Слой стоит выше модели. Экстренные службы (112, 101, 102, 103, 104) — всегда allow,
// без скоринга. Прочие короткие/сервисные номера и номера из allowlist (проверенные
// банки, госорганы) не блокируются: потолок вердикта — review. Так на вопрос «что
// будет, если система заблокирует скорую» ответ архитектурный, а не «модель, надеемся, не ошибётся».
package protect

import (
	"bufio"
	"io"
	"strings"

	"github.com/sanchyous/redflag-antifraud/internal/phone"
)

// Class — защитный класс вызова.
type Class uint8

const (
	None Class = iota
	// ServiceShort — короткий сервисный номер (0611, 900 ...) на любой стороне: потолок review.
	ServiceShort
	// Allowlisted — звонящий из списка проверенных номеров/префиксов: потолок review.
	Allowlisted
	// Emergency — экстренные службы на любой стороне: всегда allow.
	Emergency
)

var classNames = [...]string{"", "service_short", "allowlisted", "emergency"}

func (c Class) String() string {
	if int(c) < len(classNames) {
		return classNames[c]
	}
	return ""
}

// NeverBlock — класс, при котором block запрещён.
func (c Class) NeverBlock() bool { return c != None }

var emergencyShort = map[string]struct{}{
	"112": {}, "101": {}, "102": {}, "103": {}, "104": {}, "911": {},
	"001": {}, "002": {}, "003": {}, "004": {}, // старые городские коды служб
	"01": {}, "02": {}, "03": {}, "04": {},
}

// Classifier определяет защитный класс вызова. Безопасен для конкурентного чтения.
type Classifier struct {
	exact    map[string]struct{} // полные номера E.164 (цифры)
	prefixes map[string]struct{} // префиксы E.164 (цифры)
	minPfx   int
	maxPfx   int
}

// New создаёт классификатор с пустым allowlist.
func New() *Classifier {
	return &Classifier{exact: map[string]struct{}{}, prefixes: map[string]struct{}{}, minPfx: 99}
}

// LoadAllowlist читает список: по одной записи в строке, "#" — комментарий.
// Запись без "*" в конце — точный номер, с "*" — префикс: "+7 495 123*", "+7800*".
// Некорректные строки возвращаются в bad и не прерывают загрузку.
func (c *Classifier) LoadAllowlist(r io.Reader) (loaded int, bad []string) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if c.Add(line) {
			loaded++
		} else {
			bad = append(bad, line)
		}
	}
	return loaded, bad
}

// Add добавляет запись allowlist (см. LoadAllowlist). Возвращает false, если запись некорректна.
func (c *Classifier) Add(entry string) bool {
	entry = strings.TrimSpace(entry)
	isPrefix := strings.HasSuffix(entry, "*")
	entry = strings.TrimSuffix(entry, "*")
	digits := onlyDigits(entry)
	if digits == "" || len(digits) > 15 || strings.ContainsAny(entry, "*abcdefghijklmnopqrstuvwxyz") {
		return false
	}
	if isPrefix {
		if len(digits) < 4 { // слишком широкий префикс (например "+7") разрешил бы всё
			return false
		}
		c.prefixes[digits] = struct{}{}
		if len(digits) < c.minPfx {
			c.minPfx = len(digits)
		}
		if len(digits) > c.maxPfx {
			c.maxPfx = len(digits)
		}
		return true
	}
	n, err := phone.Parse(entry)
	if err != nil || !n.Complete() {
		return false
	}
	c.exact[n.Digits] = struct{}{}
	return true
}

func onlyDigits(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// Classify возвращает защитный класс вызова. Приоритет: Emergency > Allowlisted > ServiceShort.
func (c *Classifier) Classify(caller, callee phone.Number, callerValid bool) Class {
	if isEmergency(callee) || (callerValid && isEmergency(caller)) {
		return Emergency
	}
	if callerValid && c.allowed(caller) {
		return Allowlisted
	}
	if callee.Short || (callerValid && caller.Short) {
		return ServiceShort
	}
	return None
}

// IsEmergencyRaw проверяет «сырую» строку номера экстренной службы даже если она не разбирается
// как номер ("*112", "112#", "+112"). Нужна, чтобы экстренный вызов с непривычной записью
// не превратился в ошибку валидации: на любую запись экстренной службы — allow.
func IsEmergencyRaw(raw string) bool {
	d := onlyDigits(raw)
	if d == "" || len(d) > 4 {
		return false
	}
	if _, ok := emergencyShort[d]; ok {
		return true
	}
	t := strings.TrimLeft(d, "0")
	if len(t) == 3 {
		_, ok := emergencyShort[t]
		return ok
	}
	return false
}

func isEmergency(n phone.Number) bool {
	if !n.Short {
		return false
	}
	// "*112", "0112" и т.п. приходят как цифры без спецсимволов: сравниваем и целиком, и без ведущих нулей
	if _, ok := emergencyShort[n.Digits]; ok {
		return true
	}
	d := strings.TrimLeft(n.Digits, "0")
	if len(d) == 3 {
		_, ok := emergencyShort[d]
		return ok
	}
	return false
}

func (c *Classifier) allowed(n phone.Number) bool {
	if n.Short || n.Digits == "" {
		return false
	}
	if _, ok := c.exact[n.Digits]; ok {
		return true
	}
	if c.maxPfx == 0 {
		return false
	}
	for l := c.minPfx; l <= c.maxPfx && l <= len(n.Digits); l++ {
		if _, ok := c.prefixes[n.Digits[:l]]; ok {
			return true
		}
	}
	return false
}

// Size — число записей allowlist.
func (c *Classifier) Size() int { return len(c.exact) + len(c.prefixes) }
