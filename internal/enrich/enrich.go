// Package enrich превращает сырой вызов в обогащённую запись: разбор номеров, оператор и
// регион из офлайн-справочника, сигналы подмены номера (spoofing) и расхождения оператора.
package enrich

import (
	"errors"
	"strings"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/callrec"
	"github.com/sanchyous/redflag-antifraud/internal/numplan"
	"github.com/sanchyous/redflag-antifraud/internal/phone"
)

// ErrCalleeInvalid — получатель не разобран; скорить такой вызов нельзя.
var ErrCalleeInvalid = errors.New("enrich: callee is not a valid number")

// Side — обогащённая сторона вызова.
type Side struct {
	Num      phone.Number
	Valid    bool // номер разобран
	Found    bool // найден в справочнике РФ
	Operator string
	Region   string
	RegionID uint16
	NonGeo   bool
	Brand    Brand
}

// Result — обогащённый вызов. Копируется по значению; строки ссылаются на справочник.
type Result struct {
	Event  callrec.Event
	Caller Side
	Callee Side

	ConnType          callrec.ConnType
	SrcCountry        string
	SrcBrand          Brand
	LocalHour         int  // час старта в локальной зоне (0..23)
	Night             bool // ночь: [0, 6)
	ForeignIngress    bool
	Spoof             bool
	CallerUnallocated bool
	OperatorMismatch  bool
}

// Enricher безопасен для конкурентного использования.
type Enricher struct {
	Plan *numplan.Plan // nil — обогащение регионами/операторами отключено (только разбор)
	Loc  *time.Location
}

// New создаёт обогатитель. loc — зона для «времени суток» (nil → Europe/Moscow, иначе UTC+3).
func New(plan *numplan.Plan, loc *time.Location) *Enricher {
	if loc == nil {
		l, err := time.LoadLocation("Europe/Moscow")
		if err != nil {
			l = time.FixedZone("MSK", 3*3600)
		}
		loc = l
	}
	return &Enricher{Plan: plan, Loc: loc}
}

func (e *Enricher) side(raw string) Side {
	n, err := phone.Parse(raw)
	if err != nil {
		return Side{}
	}
	s := Side{Num: n, Valid: true}
	if e.Plan == nil {
		return s
	}
	info, ok := e.Plan.Lookup(n)
	if !ok {
		return s
	}
	s.Found = true
	s.Operator = info.Operator
	s.Region = info.Region
	s.RegionID = info.RegionID
	s.NonGeo = info.NonGeo
	if info.Operator != "" {
		s.Brand = brandByINN(info.INN)
	}
	return s
}

// Enrich обогащает вызов. Нечитаемый CLI не ошибка (это признак), нечитаемый получатель — ошибка.
// startedAt должен быть непустым (нулевое время подставляет вызывающий).
func (e *Enricher) Enrich(c *callrec.Call) (Result, error) {
	var r Result
	r.Callee = e.side(c.Callee)
	if !r.Callee.Valid {
		return r, ErrCalleeInvalid
	}
	r.Caller = e.side(c.Caller)
	r.ConnType, _ = callrec.ParseConnType(c.ConnType)
	r.SrcCountry = strings.ToUpper(strings.TrimSpace(c.SrcCountry))
	r.SrcBrand = brandByName(c.SrcOperator)

	lt := c.StartedAt.In(e.Loc)
	r.LocalHour = lt.Hour()
	r.Night = r.LocalHour < 6

	var flags uint16
	answered := c.IsAnswered()
	if answered {
		flags |= callrec.FlagAnswered
		if c.DurationSec <= 1 {
			flags |= callrec.FlagHangup1s
		}
	}

	// Вход из-за рубежа: страна источника не РФ либо международный транзит.
	r.ForeignIngress = (r.SrcCountry != "" && r.SrcCountry != "RU") || r.ConnType == callrec.ConnInternational
	if r.ForeignIngress {
		flags |= callrec.FlagForeignIngress
	}

	switch {
	case !r.Caller.Valid:
		flags |= callrec.FlagCallerInvalid
	case r.Caller.Num.IsRU() && !r.Caller.Num.Short:
		// Российский CLI при иностранном входе — подмена номера (CLI spoofing).
		if r.ForeignIngress {
			r.Spoof = true
			flags |= callrec.FlagSpoof
		}
		// Полный российский номер вне распределённых диапазонов: реальный абонент так не звонит.
		if e.Plan != nil && r.Caller.Num.Complete() && !r.Caller.Found {
			r.CallerUnallocated = true
			flags |= callrec.FlagCallerUnallocated
		}
		// Оператор из сигнализации не совпадает с держателем диапазона. Слабый сигнал:
		// возможна переносимость номера (MNP), поэтому только для распознанных крупных брендов.
		if !r.ForeignIngress && r.SrcBrand != BrandUnknown && r.Caller.Brand != BrandUnknown &&
			r.SrcBrand != r.Caller.Brand {
			r.OperatorMismatch = true
			flags |= callrec.FlagOperatorMismatch
		}
	}

	dur := c.DurationSec
	if dur < 0 {
		dur = 0
	}
	r.Event = callrec.Event{
		TS:           c.StartedAt.Unix(),
		Caller:       callerKey(r.Caller),
		Callee:       r.Callee.Num.Key(),
		DurSec:       uint32(dur),
		CallerRegion: r.Caller.RegionID,
		CalleeRegion: r.Callee.RegionID,
		Flags:        flags,
	}
	return r, nil
}

// callerKey: нечитаемый/анонимный CLI получает общий ключ 0 (все анонимные — «один абонент»).
func callerKey(s Side) uint64 {
	if !s.Valid {
		return 0
	}
	return s.Num.Key()
}
