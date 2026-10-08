// Package callrec — модель «конверта» вызова (метаданные сигнализации, без содержимого
// разговора) и компактное событие для горячего пути скоринга.
package callrec

import (
	"strings"
	"time"
)

// ConnType — тип соединения.
type ConnType uint8

const (
	ConnUnknown ConnType = iota
	ConnMobile
	ConnFixed
	ConnInternational
	ConnVoIP
)

var connNames = [...]string{"unknown", "mobile", "fixed", "international", "voip"}

func (c ConnType) String() string {
	if int(c) < len(connNames) {
		return connNames[c]
	}
	return connNames[0]
}

// ParseConnType разбирает строку из API; пустая строка и неизвестные значения — ConnUnknown, ok=false для второго.
func ParseConnType(s string) (ConnType, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return ConnUnknown, true
	case "mobile", "gsm", "cell":
		return ConnMobile, true
	case "fixed", "landline", "pstn":
		return ConnFixed, true
	case "international", "intl", "transit":
		return ConnInternational, true
	case "voip", "sip":
		return ConnVoIP, true
	}
	return ConnUnknown, false
}

// Direction — роль записи в сигнализации коммутатора: кто кому звонил и не было ли переадресации.
// Большинство источников этого не присылают (DirUnknown) — тогда вызов считается исходящим от
// Caller, как раньше. Приходит из сигнализации, не выводится из Caller/Callee.
type Direction uint8

const (
	DirUnknown Direction = iota
	DirIncoming
	DirOutgoing
	DirForwarded
)

var dirNames = [...]string{"", "incoming", "outgoing", "forwarded"}

func (d Direction) String() string {
	if int(d) < len(dirNames) {
		return dirNames[d]
	}
	return ""
}

// ParseDirection разбирает строку из API; пустая строка — DirUnknown, ok=false для нераспознанной.
func ParseDirection(s string) (Direction, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return DirUnknown, true
	case "incoming", "in", "01":
		return DirIncoming, true
	case "outgoing", "out", "02":
		return DirOutgoing, true
	case "forwarded", "forward", "03":
		return DirForwarded, true
	}
	return DirUnknown, false
}

// Call — вызов в том виде, в каком он приходит по API. Номера — как есть (полные или маски).
type Call struct {
	CallID      string    `json:"call_id"`
	Caller      string    `json:"caller"`
	Callee      string    `json:"callee"`
	StartedAt   time.Time `json:"started_at"`
	DurationSec int       `json:"duration_sec"`
	// Answered — вызов принят абонентом. Если поле не передано, считается answered = duration_sec > 0.
	Answered *bool `json:"answered,omitempty"`
	// ConnType — mobile|fixed|international|voip (пусто — неизвестно).
	ConnType string `json:"conn_type,omitempty"`
	// SrcCountry — ISO-код страны источника из сигнализации, SrcOperator — оператор источника.
	SrcCountry  string `json:"src_country,omitempty"`
	SrcOperator string `json:"src_operator,omitempty"`
	// SubscriberID — идентификатор абонента у оператора (для «номеров на одного абонента»); необязателен.
	SubscriberID string `json:"subscriber_id,omitempty"`
	// IMSI — идентификатор SIM вызывающего из сигнализации. Один номер с россыпью разных IMSI —
	// признак клонирования SIM/подмены модуля идентификации (детектор: internal/detection/graph.Idents).
	IMSI string `json:"imsi,omitempty"`
	// Direction — входящий/исходящий/переадресация с точки зрения коммутатора; пусто — неизвестно
	// (считается исходящим от Caller). ForwardTo обязателен при Direction == DirForwarded.
	Direction Direction `json:"direction,omitempty"`
	// ForwardTo — куда Callee переадресовал вызов (при Direction == DirForwarded).
	ForwardTo string `json:"forward_to,omitempty"`
}

const (
	maxDurationSec = 24 * 3600
	maxIDLen       = 128
)

// Validate проверяет структурную целостность входа (не антифрод). Возвращает коды ошибок.
// maxFuture > 0 включает проверку «вызов из будущего» (допустимый уход часов вперёд); 0 — проверка
// выключена (нужно при проигрывании исторических данных и когда часы источника не синхронизированы).
// Нулевой StartedAt допустим — его подставит сервис.
func (c *Call) Validate(now time.Time, maxFuture time.Duration) []string {
	var errs []string
	if c.CallID == "" {
		errs = append(errs, "call_id_required")
	} else if len(c.CallID) > maxIDLen {
		errs = append(errs, "call_id_too_long")
	}
	if strings.TrimSpace(c.Callee) == "" {
		errs = append(errs, "callee_required")
	}
	if c.DurationSec < 0 {
		errs = append(errs, "duration_negative")
	} else if c.DurationSec > maxDurationSec {
		errs = append(errs, "duration_too_long")
	}
	if maxFuture > 0 && !c.StartedAt.IsZero() && c.StartedAt.After(now.Add(maxFuture)) {
		errs = append(errs, "started_at_in_future")
	}
	if _, ok := ParseConnType(c.ConnType); !ok {
		errs = append(errs, "conn_type_invalid")
	}
	if c.Answered != nil && !*c.Answered && c.DurationSec > 0 {
		errs = append(errs, "unanswered_with_duration")
	}
	if c.SrcCountry != "" && len(c.SrcCountry) != 2 {
		errs = append(errs, "src_country_invalid")
	}
	if c.Direction > DirForwarded {
		errs = append(errs, "direction_invalid")
	}
	if c.Direction == DirForwarded && strings.TrimSpace(c.ForwardTo) == "" {
		errs = append(errs, "forward_to_required")
	}
	return errs
}

// IsAnswered — вызов принят (с учётом умолчания).
func (c *Call) IsAnswered() bool {
	if c.Answered != nil {
		return *c.Answered
	}
	return c.DurationSec > 0
}

// Флаги события.
const (
	FlagAnswered          uint16 = 1 << iota
	FlagHangup1s                 // длительность <= 1 с у принятого вызова
	FlagForeignIngress           // вход из-за рубежа / международный транзит
	FlagSpoof                    // российский CLI при иностранном входе
	FlagCallerUnallocated        // российский CLI из нераспределённого диапазона
	FlagCallerInvalid            // CLI отсутствует или не разобран
	FlagOperatorMismatch
)

// Event — компактная запись для окон и графа: без строк, копируется по значению.
type Event struct {
	TS           int64  // unix-секунды старта
	Caller       uint64 // phone.Number.Key()
	Callee       uint64
	DurSec       uint32
	CallerRegion uint16 // numplan RegionID, 0 — неизвестен
	CalleeRegion uint16
	Flags        uint16
	Subscriber   uint64 // хэш subscriber_id, 0 — неизвестен
	IMSI         uint64 // хэш IMSI вызывающего, 0 — неизвестен (детектор клонов SIM)
	ForwardTo    uint64 // phone.Number.Key() цели переадресации, 0 — не переадресован
}

// Has проверяет наличие флага.
func (e *Event) Has(f uint16) bool { return e.Flags&f != 0 }
