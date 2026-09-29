// Package synth генерирует размеченные синтетические потоки вызовов для обучения и оценки.
//
// Главное в наборе — «трудные» легитимные абоненты, похожие на мошенников по одному-двум
// признакам: колл-центры (много уникальных адресатов), банковские уведомления (обзвон всей
// страны), курьеры (много коротких вызовов), абоненты в роуминге (российский номер при
// иностранном входе), компании с десятками номеров. Без них модель научится ловить просто
// «много и коротко» и будет блокировать честных. Генератор детерминирован по Seed.
package synth

import (
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"time"

	"github.com/sanchyous/redflag-antifraud/internal/callrec"
	"github.com/sanchyous/redflag-antifraud/internal/numplan"
	"github.com/sanchyous/redflag-antifraud/internal/phone"
)

// Kind — тип абонента-источника.
type Kind string

// Легитимные типы.
const (
	KindRegular       Kind = "regular"
	KindHeavy         Kind = "heavy_user"
	KindCallCenter    Kind = "call_center"
	KindBankNotify    Kind = "bank_notify"
	KindCourier       Kind = "courier"
	KindRoamer        Kind = "roamer"
	KindForeignCaller Kind = "foreign_caller"
	KindCorpMulti     Kind = "corp_multi"
	KindEmergency     Kind = "emergency"
)

// Мошеннические типы.
const (
	KindSpoofBurst Kind = "spoof_burst"
	KindRobocall   Kind = "robocall"
	KindOneRing    Kind = "one_ring"
	KindFan        Kind = "fan"
	KindSimFarm    Kind = "sim_farm"
	KindColdSpam   Kind = "cold_spam"
)

// FraudKinds — все мошеннические типы.
var FraudKinds = []Kind{KindSpoofBurst, KindRobocall, KindOneRing, KindFan, KindSimFarm, KindColdSpam}

// LegitKinds — все легитимные типы.
var LegitKinds = []Kind{KindRegular, KindHeavy, KindCallCenter, KindBankNotify, KindCourier, KindRoamer,
	KindForeignCaller, KindCorpMulti, KindEmergency}

// IsFraud сообщает, мошеннический ли тип.
func (k Kind) IsFraud() bool {
	for _, f := range FraudKinds {
		if k == f {
			return true
		}
	}
	return false
}

// Sample — вызов с меткой.
type Sample struct {
	Call  callrec.Call
	Fraud bool
	Kind  Kind
}

// Dataset — набор вызовов по времени и список проверенных номеров (для allowlist).
type Dataset struct {
	Samples   []Sample
	Allowlist []string // проверенные номера (часть банков): для protect.Classifier
}

// Config — параметры генерации. Нулевые счётчики заменяются значениями по умолчанию
// с учётом Scale.
type Config struct {
	Seed  uint64
	Plan  *numplan.Plan // обязателен: номера берутся из распределённых диапазонов
	Start time.Time     // начало моделируемого периода (по умолчанию 2026-03-02 00:00 MSK)
	Days  int           // длина периода (по умолчанию 3)
	Scale float64       // множитель числа абонентов (по умолчанию 1)

	// Число абонентов по типам (0 → значение по умолчанию × Scale; отрицательное → 0).
	Regular, Heavy, CallCenters, BankNotify, Couriers, Roamers, ForeignCallers, CorpMulti, Emergency int
	SpoofBurst, Robocall, OneRing, FanGroups, SimFarms, ColdSpam                                     int
}

var msk = time.FixedZone("MSK", 3*3600)

func (c *Config) defaults() {
	if c.Start.IsZero() {
		c.Start = time.Date(2026, 3, 2, 0, 0, 0, 0, msk)
	}
	if c.Days <= 0 {
		c.Days = 3
	}
	if c.Scale <= 0 {
		c.Scale = 1
	}
	set := func(v *int, def int) {
		switch {
		case *v < 0:
			*v = 0
		case *v == 0:
			*v = max(1, int(math.Round(float64(def)*c.Scale))) // каждый тип представлен хотя бы одним абонентом
		}
	}
	// Пропорции подобраны так, чтобы обычные абоненты давали основную часть трафика (как в сети),
	// а трудные легитимные случаи были представлены достаточно, чтобы считать по ним FPR отдельно.
	set(&c.Regular, 6000)
	set(&c.Heavy, 60)
	set(&c.CallCenters, 6)
	set(&c.BankNotify, 4)
	set(&c.Couriers, 30)
	set(&c.Roamers, 60)
	set(&c.ForeignCallers, 100)
	set(&c.CorpMulti, 3)
	set(&c.Emergency, 150)
	set(&c.SpoofBurst, 12)
	set(&c.Robocall, 6)
	set(&c.OneRing, 8)
	set(&c.FanGroups, 3)
	set(&c.SimFarms, 4)
	set(&c.ColdSpam, 60)
}

type gen struct {
	cfg     Config
	rng     *rand.Rand
	plan    *numplan.Plan
	regions []uint16
	out     []Sample
	allow   []string
	seq     int
	end     time.Time
}

// Generate создаёт набор. Вызовы упорядочены по времени начала.
func Generate(cfg Config) *Dataset {
	cfg.defaults()
	g := &gen{cfg: cfg, plan: cfg.Plan, rng: rand.New(rand.NewPCG(cfg.Seed, cfg.Seed^0x9E3779B97F4A7C15))}
	g.regions = g.plan.RegionIDs()
	g.end = cfg.Start.Add(time.Duration(cfg.Days) * 24 * time.Hour)

	for i := 0; i < cfg.Regular; i++ {
		g.regular()
	}
	for i := 0; i < cfg.Heavy; i++ {
		g.heavy()
	}
	for i := 0; i < cfg.CallCenters; i++ {
		g.callCenter()
	}
	for i := 0; i < cfg.BankNotify; i++ {
		g.bankNotify(i%2 == 0) // половина банков — в allowlist
	}
	for i := 0; i < cfg.Couriers; i++ {
		g.courier()
	}
	for i := 0; i < cfg.Roamers; i++ {
		g.roamer()
	}
	for i := 0; i < cfg.ForeignCallers; i++ {
		g.foreignCaller()
	}
	for i := 0; i < cfg.CorpMulti; i++ {
		g.corpMulti()
	}
	for i := 0; i < cfg.Emergency; i++ {
		g.emergency()
	}
	for i := 0; i < cfg.SpoofBurst; i++ {
		g.spoofBurst()
	}
	for i := 0; i < cfg.Robocall; i++ {
		g.robocall()
	}
	for i := 0; i < cfg.OneRing; i++ {
		g.oneRing()
	}
	for i := 0; i < cfg.FanGroups; i++ {
		g.fan()
	}
	for i := 0; i < cfg.SimFarms; i++ {
		g.simFarm()
	}
	for i := 0; i < cfg.ColdSpam; i++ {
		g.coldSpam()
	}

	sort.SliceStable(g.out, func(i, j int) bool { return g.out[i].Call.StartedAt.Before(g.out[j].Call.StartedAt) })
	return &Dataset{Samples: g.out, Allowlist: g.allow}
}

// ---- примитивы ----

func (g *gen) intn(lo, hi int) int   { return lo + g.rng.IntN(hi-lo+1) }
func (g *gen) chance(p float64) bool { return g.rng.Float64() < p }

func (g *gen) logNormal(median, sigma float64) float64 {
	return median * math.Exp(sigma*g.rng.NormFloat64())
}

func (g *gen) anyRegion() uint16 { return g.regions[g.rng.IntN(len(g.regions))] }

func (g *gen) number(region uint16) string {
	s, ok := g.plan.RandomNumber(g.rng, region)
	if !ok {
		s, _ = g.plan.RandomNumber(g.rng, 0)
	}
	return s
}

func (g *gen) regionOf(num string) uint16 {
	n, err := phone.Parse(num)
	if err != nil {
		return 0
	}
	info, ok := g.plan.Lookup(n)
	if !ok {
		return 0
	}
	return info.RegionID
}

func (g *gen) operatorOf(num string) string {
	n, err := phone.Parse(num)
	if err != nil {
		return ""
	}
	info, _ := g.plan.Lookup(n)
	return info.Operator
}

var otherOperators = []string{"МТС", "МегаФон", "Билайн", "Tele2", "Ростелеком"}

// mnpOperator возвращает оператора источника: обычно совпадает с держателем диапазона,
// в ~8% случаев — «перенесённый» номер (другой бренд).
func (g *gen) srcOperator(caller string) string {
	if g.chance(0.08) {
		return otherOperators[g.rng.IntN(len(otherOperators))]
	}
	return g.operatorOf(caller)
}

func (g *gen) connType(caller string) string {
	if len(caller) > 2 && caller[2] == '9' {
		return "mobile"
	}
	return "fixed"
}

func (g *gen) unallocated() string {
	for i := 0; i < 1000; i++ {
		s := fmt.Sprintf("+7%03d%07d", g.rng.IntN(900)+100, g.rng.IntN(10_000_000))
		n, err := phone.Parse(s)
		if err != nil {
			continue
		}
		if _, found := g.plan.Lookup(n); !found && n.ISO == "RU" {
			return s
		}
	}
	return "+79999999999"
}

var foreignCountries = []struct{ iso, cc string }{
	{"DE", "49"}, {"GB", "44"}, {"CY", "357"}, {"PL", "48"}, {"UA", "380"}, {"US", "1"}, {"TR", "90"}, {"AE", "971"}, {"IN", "91"},
}

func (g *gen) foreignNumber(cc string) string {
	return fmt.Sprintf("+%s%09d", cc, g.rng.IntN(1_000_000_000))
}

func (g *gen) add(kind Kind, c callrec.Call) {
	g.seq++
	c.CallID = fmt.Sprintf("s%d-%08d", g.cfg.Seed, g.seq)
	answered := c.DurationSec > 0
	if c.Answered == nil {
		c.Answered = &answered
	}
	g.out = append(g.out, Sample{Call: c, Fraud: kind.IsFraud(), Kind: kind})
}

// diurnal: вес часа суток (местное время): ночью звонков мало, пики — утро и вечер.
var diurnal = [24]float64{0.2, 0.1, 0.1, 0.1, 0.2, 0.5, 1.2, 3, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 6, 4, 2, 0.8}
var diurnalCum = func() [24]float64 {
	var c [24]float64
	var s float64
	for i, w := range diurnal {
		s += w
		c[i] = s
	}
	return c
}()

func (g *gen) humanTime(day int) time.Time {
	x := g.rng.Float64() * diurnalCum[23]
	h := 0
	for h < 23 && diurnalCum[h] < x {
		h++
	}
	return g.cfg.Start.AddDate(0, 0, day).Add(time.Duration(h)*time.Hour + time.Duration(g.rng.IntN(3600))*time.Second)
}

// contacts — список контактов: доля своего региона задаётся localShare.
func (g *gen) contacts(n int, region uint16, localShare float64) []string {
	out := make([]string, n)
	for i := range out {
		if g.chance(localShare) {
			out[i] = g.number(region)
		} else {
			out[i] = g.number(0)
		}
	}
	return out
}

// pick выбирает контакт с убывающей вероятностью (близкие контакты — чаще).
func (g *gen) pick(list []string) string {
	u := g.rng.Float64()
	i := int(float64(len(list)) * u * u)
	if i >= len(list) {
		i = len(list) - 1
	}
	return list[i]
}

func (g *gen) durAnswered(median, sigma float64) int {
	d := int(g.logNormal(median, sigma))
	if d < 1 {
		d = 1
	}
	if d > 7200 {
		d = 7200
	}
	return d
}

// ---- легитимные ----

func (g *gen) humanCaller(kind Kind, perDay [2]int, contactN [2]int, answeredP, median, sigma float64, subscriber string) {
	region := g.anyRegion()
	caller := g.number(region)
	list := g.contacts(g.intn(contactN[0], contactN[1]), region, 0.7)
	for day := 0; day < g.cfg.Days; day++ {
		n := g.intn(perDay[0], perDay[1])
		for i := 0; i < n; i++ {
			c := callrec.Call{
				Caller: caller, Callee: g.pick(list), StartedAt: g.humanTime(day),
				ConnType: g.connType(caller), SrcCountry: "RU", SrcOperator: g.srcOperator(caller), SubscriberID: subscriber,
			}
			if g.chance(answeredP) {
				if g.chance(0.05) {
					c.DurationSec = g.intn(1, 9) // ошиблись номером, сбросили
				} else {
					c.DurationSec = g.durAnswered(median, sigma)
				}
			}
			g.add(kind, c)
		}
	}
}

func (g *gen) regular() {
	sub := ""
	if g.chance(0.15) { // у части абонентов несколько своих номеров
		sub = fmt.Sprintf("sub-%d-%d", g.cfg.Seed, g.rng.IntN(1<<30))
		if g.chance(0.5) {
			g.humanCaller(KindRegular, [2]int{0, 6}, [2]int{3, 12}, 0.85, 75, 1.0, sub)
		}
	}
	g.humanCaller(KindRegular, [2]int{0, 14}, [2]int{4, 25}, 0.85, 75, 1.0, sub)
}

func (g *gen) heavy() {
	g.humanCaller(KindHeavy, [2]int{30, 120}, [2]int{15, 60}, 0.8, 45, 1.0, "")
}

func (g *gen) callCenter() {
	region := g.anyRegion()
	pool := g.contacts(400, region, 0.7)
	agents := g.intn(1, 3)
	for a := 0; a < agents; a++ {
		caller := g.number(region)
		for day := 0; day < g.cfg.Days; day++ {
			t := g.cfg.Start.AddDate(0, 0, day).Add(9 * time.Hour)
			endT := g.cfg.Start.AddDate(0, 0, day).Add(19 * time.Hour)
			rate := float64(g.intn(20, 45)) / 3600 // вызовов в секунду
			for {
				t = t.Add(time.Duration(g.rng.ExpFloat64()/rate) * time.Second)
				if !t.Before(endT) {
					break
				}
				c := callrec.Call{Caller: caller, Callee: g.pick(pool), StartedAt: t, ConnType: g.connType(caller),
					SrcCountry: "RU", SrcOperator: g.srcOperator(caller)}
				if g.chance(0.45) {
					c.DurationSec = g.durAnswered(50, 0.9)
				}
				g.add(KindCallCenter, c)
			}
		}
	}
}

func (g *gen) bankNotify(allowlisted bool) {
	for k := 0; k < g.intn(1, 3); k++ {
		caller := g.number(0)
		if allowlisted {
			g.allow = append(g.allow, caller)
		}
		for day := 0; day < g.cfg.Days; day++ {
			n := g.intn(300, 700)
			for i := 0; i < n; i++ {
				c := callrec.Call{Caller: caller, Callee: g.number(0), StartedAt: g.humanTime(day), ConnType: g.connType(caller),
					SrcCountry: "RU", SrcOperator: g.srcOperator(caller)}
				if g.chance(0.55) {
					c.DurationSec = g.durAnswered(25, 0.5)
				}
				g.add(KindBankNotify, c)
			}
		}
	}
}

func (g *gen) courier() {
	region := g.anyRegion()
	caller := g.number(region)
	for day := 0; day < g.cfg.Days; day++ {
		n := g.intn(20, 50)
		for i := 0; i < n; i++ {
			c := callrec.Call{Caller: caller, Callee: g.number(region), StartedAt: g.humanTime(day), ConnType: "mobile",
				SrcCountry: "RU", SrcOperator: g.srcOperator(caller)}
			if g.chance(0.7) {
				c.DurationSec = g.durAnswered(20, 0.6)
			}
			g.add(KindCourier, c)
		}
	}
}

// roamer — абонент за границей. Его вызов входит в сеть как домашний (через собственную сеть
// оператора), а не через международный транзит, поэтому вход выглядит российским. Небольшая доля
// таких абонентов — легитимные SIP-транки и облачные АТС российских компаний через зарубежных
// операторов: российский номер при иностранном входе, но не подмена. Это единственный трудный
// легитимный случай для признака spoof, и он нарочно редок.
func (g *gen) roamer() {
	region := g.anyRegion()
	caller := g.number(region)
	list := g.contacts(g.intn(4, 15), region, 0.8)
	connType, country := "mobile", "RU"
	if g.chance(0.10) {
		connType, country = "international", foreignCountries[g.rng.IntN(len(foreignCountries))].iso
	}
	for day := 0; day < g.cfg.Days; day++ {
		n := g.intn(3, 8)
		for i := 0; i < n; i++ {
			c := callrec.Call{Caller: caller, Callee: g.pick(list), StartedAt: g.humanTime(day), ConnType: connType,
				SrcCountry: country, SrcOperator: g.operatorOf(caller)}
			if g.chance(0.8) {
				c.DurationSec = g.durAnswered(90, 0.9)
			}
			g.add(KindRoamer, c)
		}
	}
}

func (g *gen) foreignCaller() {
	fc := foreignCountries[g.rng.IntN(len(foreignCountries))]
	caller := g.foreignNumber(fc.cc)
	list := g.contacts(g.intn(2, 6), g.anyRegion(), 0.6)
	for day := 0; day < g.cfg.Days; day++ {
		n := g.intn(0, 4)
		for i := 0; i < n; i++ {
			c := callrec.Call{Caller: caller, Callee: g.pick(list), StartedAt: g.humanTime(day), ConnType: "international",
				SrcCountry: fc.iso}
			if g.chance(0.8) {
				c.DurationSec = g.durAnswered(120, 0.9)
			}
			g.add(KindForeignCaller, c)
		}
	}
}

func (g *gen) corpMulti() {
	sub := fmt.Sprintf("corp-%d-%d", g.cfg.Seed, g.rng.IntN(1<<30))
	region := g.anyRegion()
	numbers := g.intn(10, 30)
	for k := 0; k < numbers; k++ {
		caller := g.number(region)
		list := g.contacts(g.intn(10, 40), region, 0.6)
		for day := 0; day < g.cfg.Days; day++ {
			n := g.intn(5, 30)
			for i := 0; i < n; i++ {
				c := callrec.Call{Caller: caller, Callee: g.pick(list), StartedAt: g.humanTime(day), ConnType: g.connType(caller),
					SrcCountry: "RU", SrcOperator: g.srcOperator(caller), SubscriberID: sub}
				if g.chance(0.75) {
					c.DurationSec = g.durAnswered(70, 0.9)
				}
				g.add(KindCorpMulti, c)
			}
		}
	}
}

var emergencyNumbers = []string{"112", "103", "101", "102", "112", "103"}

func (g *gen) emergency() {
	region := g.anyRegion()
	caller := g.number(region)
	n := g.intn(1, 3)
	for i := 0; i < n; i++ {
		g.add(KindEmergency, callrec.Call{Caller: caller, Callee: emergencyNumbers[g.rng.IntN(len(emergencyNumbers))],
			StartedAt: g.humanTime(g.rng.IntN(g.cfg.Days)), DurationSec: g.durAnswered(90, 0.7), ConnType: "mobile", SrcCountry: "RU"})
	}
}

// ---- мошенничество ----

func (g *gen) randomTimeIn(from, to time.Time) time.Time {
	return from.Add(time.Duration(g.rng.Int64N(int64(to.Sub(from)))))
}

func (g *gen) spoofBurst() {
	caller := g.unallocated()
	if g.chance(0.5) {
		caller = g.number(0) // подмена чужого настоящего номера
	}
	fc := foreignCountries[g.rng.IntN(len(foreignCountries))]
	day := g.rng.IntN(g.cfg.Days)
	start := g.cfg.Start.AddDate(0, 0, day).Add(time.Duration(g.intn(8, 18)) * time.Hour)
	total := g.intn(200, 800)
	hours := g.intn(3, 8)
	mean := float64(hours*3600) / float64(total)
	t := start
	for i := 0; i < total; i++ {
		t = t.Add(time.Duration(g.rng.ExpFloat64()*mean) * time.Second)
		c := callrec.Call{Caller: caller, Callee: g.number(0), StartedAt: t, ConnType: "international", SrcCountry: fc.iso,
			SrcOperator: otherOperators[g.rng.IntN(len(otherOperators))]}
		if g.chance(0.3) {
			c.DurationSec = g.durAnswered(6, 0.6)
		}
		g.add(KindSpoofBurst, c)
	}
}

func (g *gen) robocall() {
	sims := g.intn(1, 3)
	for k := 0; k < sims; k++ {
		caller := g.number(g.anyRegion())
		total := g.intn(300, 900)
		gap := float64(g.intn(20, 60))
		t := g.randomTimeIn(g.cfg.Start, g.end.Add(-time.Duration(float64(total)*gap)*time.Second))
		for i := 0; i < total; i++ {
			t = t.Add(time.Duration(gap*(0.95+g.rng.Float64()*0.1)) * time.Second)
			c := callrec.Call{Caller: caller, Callee: g.number(0), StartedAt: t, ConnType: g.connType(caller),
				SrcCountry: "RU", SrcOperator: g.operatorOf(caller)}
			if g.chance(0.15) {
				c.DurationSec = g.intn(1, 6)
			}
			g.add(KindRobocall, c)
		}
	}
}

func (g *gen) oneRing() {
	fc := foreignCountries[g.rng.IntN(len(foreignCountries))]
	caller := g.foreignNumber(fc.cc)
	total := g.intn(200, 500)
	hours := g.intn(2, 4)
	start := g.randomTimeIn(g.cfg.Start, g.end.Add(-time.Duration(hours)*time.Hour))
	mean := float64(hours*3600) / float64(total)
	t := start
	for i := 0; i < total; i++ {
		t = t.Add(time.Duration(g.rng.ExpFloat64()*mean) * time.Second)
		g.add(KindOneRing, callrec.Call{Caller: caller, Callee: g.number(0), StartedAt: t, ConnType: "international", SrcCountry: fc.iso})
	}
}

func (g *gen) fan() {
	size := g.intn(5, 15)
	region := g.anyRegion()
	base, _ := g.plan.RandomNumber(g.rng, region) // ферма SIM: подряд идущие номера
	bn, _ := phone.Parse(base)
	baseVal := parseUint(bn.National)
	gap := float64(g.intn(40, 60))
	perNumber := g.intn(100, 250)
	start := g.randomTimeIn(g.cfg.Start, g.end.Add(-time.Duration(float64(perNumber)*gap)*time.Second))
	for i := 0; i < size; i++ {
		caller := "+7" + fmt.Sprintf("%010d", baseVal+uint64(i))
		t := start.Add(time.Duration(g.rng.IntN(30)) * time.Second)
		for j := 0; j < perNumber; j++ {
			t = t.Add(time.Duration(gap*(0.8+g.rng.Float64()*0.4)) * time.Second)
			c := callrec.Call{Caller: caller, Callee: g.number(0), StartedAt: t, ConnType: "mobile",
				SrcCountry: "RU", SrcOperator: g.operatorOf(caller)}
			if g.chance(0.5) {
				c.DurationSec = g.intn(2, 8)
			}
			g.add(KindFan, c)
		}
	}
}

func (g *gen) simFarm() {
	sub := fmt.Sprintf("farm-%d-%d", g.cfg.Seed, g.rng.IntN(1<<30))
	numbers := g.intn(10, 25)
	for k := 0; k < numbers; k++ {
		caller := g.number(g.anyRegion())
		n := g.intn(40, 80)
		start := g.randomTimeIn(g.cfg.Start, g.end.Add(-2*time.Hour))
		t := start
		for i := 0; i < n; i++ {
			t = t.Add(time.Duration(g.rng.ExpFloat64()*90) * time.Second)
			c := callrec.Call{Caller: caller, Callee: g.number(0), StartedAt: t, ConnType: "mobile", SrcCountry: "RU",
				SrcOperator: g.operatorOf(caller), SubscriberID: sub}
			if g.chance(0.4) {
				c.DurationSec = g.intn(5, 20)
			}
			g.add(KindSimFarm, c)
		}
	}
}

func (g *gen) coldSpam() {
	caller := g.number(g.anyRegion())
	for day := 0; day < g.cfg.Days; day++ {
		n := g.intn(20, 40)
		for i := 0; i < n; i++ {
			c := callrec.Call{Caller: caller, Callee: g.number(0), StartedAt: g.humanTime(day), ConnType: "mobile",
				SrcCountry: "RU", SrcOperator: g.operatorOf(caller)}
			if g.chance(0.35) {
				c.DurationSec = g.durAnswered(15, 0.7)
			}
			g.add(KindColdSpam, c)
		}
	}
}

func parseUint(s string) uint64 {
	var v uint64
	for i := 0; i < len(s); i++ {
		v = v*10 + uint64(s[i]-'0')
	}
	return v
}
