// Package features собирает вектор признаков вызова для модели из обогащённого вызова,
// окон по номерам, графа и счётчика абонентов. Вектор — массив фиксированной длины
// (без аллокаций); в нём и «сырые» значения (для объяснений), и преобразованные (для модели).
package features

import (
	"math"

	"github.com/sanchyous/redflag-antifraud/internal/detection/enrich"
	"github.com/sanchyous/redflag-antifraud/internal/detection/graph"
	"github.com/sanchyous/redflag-antifraud/internal/detection/window"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/callrec"
)

// Индексы признаков. Порядок — часть контракта с файлом модели.
const (
	OutCalls1h = iota
	OutCalls24h
	OutPeers1h
	OutPeers24h
	OutNovelty
	OutRegions24h
	OutRegionEntropy
	OutShortShare
	OutUnansweredShare
	OutGapRobot
	InCalls1h
	InPeers24h
	CallShort
	CallHangup1s
	CallUnanswered
	CallNight
	CallDuration
	ForeignIngress
	Spoof
	CallerUnallocated
	CallerInvalid
	OperatorMismatch
	ConnInternational
	FanMember
	FanSize
	SubscriberNumbers
	N // число признаков
)

// Names — стабильные имена признаков (в JSON модели и в объяснениях).
var Names = [N]string{
	"out_calls_1h", "out_calls_24h", "out_peers_1h", "out_peers_24h", "out_novelty",
	"out_regions_24h", "out_region_entropy", "out_short_share", "out_unanswered_share", "out_gap_robot",
	"in_calls_1h", "in_peers_24h",
	"call_short", "call_hangup_1s", "call_unanswered", "call_night", "call_duration",
	"foreign_ingress", "spoof", "caller_unallocated", "caller_invalid", "operator_mismatch", "conn_international",
	"fan_member", "fan_size", "subscriber_numbers",
}

// logScaled — признаки, которые к модели идут как log1p (тяжёлые хвосты счётчиков).
var logScaled = [N]bool{
	OutCalls1h: true, OutCalls24h: true, OutPeers1h: true, OutPeers24h: true, OutRegions24h: true,
	InCalls1h: true, InPeers24h: true, CallDuration: true, FanSize: true, SubscriberNumbers: true,
}

// Vector — признаки одного вызова.
type Vector struct {
	Raw [N]float32 // значения в исходных единицах
	X   [N]float32 // вход модели (log1p там, где нужно)
}

// Input — всё, что нужно для сборки вектора.
type Input struct {
	Res       *enrich.Result
	Win       window.Features
	Fan       graph.FanInfo
	InFan     bool
	SubNums   int // число номеров абонента (0 — неизвестно)
	ShortSec  int // порог «короткого» разговора (по умолчанию 10)
	DurationS uint32
}

const minEvidence = 5 // минимум вызовов, чтобы доли и «новизна» имели смысл

// Build заполняет вектор. Функция чистая: без аллокаций и побочных эффектов.
func Build(in *Input, v *Vector) {
	*v = Vector{}
	r := in.Res
	shortSec := in.ShortSec
	if shortSec <= 0 {
		shortSec = 10
	}
	o, i := &in.Win.Out, &in.Win.In
	raw := &v.Raw

	raw[OutCalls1h] = float32(o.Calls1h)
	raw[OutCalls24h] = float32(o.Calls24h)
	raw[OutPeers1h] = float32(o.Peers1h)
	raw[OutPeers24h] = float32(o.Peers24h)
	if o.Calls24h >= minEvidence {
		raw[OutNovelty] = float32(o.Peers24h) / float32(o.Calls24h)
		if raw[OutNovelty] > 1 {
			raw[OutNovelty] = 1
		}
		raw[OutShortShare] = o.ShortShare
		raw[OutUnansweredShare] = o.UnansweredShare
	}
	raw[OutRegions24h] = float32(o.Regions24h)
	raw[OutRegionEntropy] = o.RegionEntropy
	if o.Calls1h >= 6 && o.GapMeanSec > 0 {
		raw[OutGapRobot] = clamp01(1 - o.GapCV)
	}
	raw[InCalls1h] = float32(i.Calls1h)
	raw[InPeers24h] = float32(i.Peers24h)

	ev := &r.Event
	answered := ev.Has(callrec.FlagAnswered)
	raw[CallShort] = b2f(answered && int(ev.DurSec) < shortSec)
	raw[CallHangup1s] = b2f(ev.Has(callrec.FlagHangup1s))
	raw[CallUnanswered] = b2f(!answered)
	raw[CallNight] = b2f(r.Night)
	raw[CallDuration] = float32(ev.DurSec)
	raw[ForeignIngress] = b2f(r.ForeignIngress)
	raw[Spoof] = b2f(r.Spoof)
	raw[CallerUnallocated] = b2f(r.CallerUnallocated)
	raw[CallerInvalid] = b2f(ev.Has(callrec.FlagCallerInvalid))
	raw[OperatorMismatch] = b2f(r.OperatorMismatch)
	raw[ConnInternational] = b2f(r.ConnType == callrec.ConnInternational)
	if in.InFan {
		raw[FanMember] = 1
		raw[FanSize] = float32(in.Fan.Size)
	}
	if in.SubNums > 1 {
		raw[SubscriberNumbers] = float32(in.SubNums - 1) // «лишние» номера сверх первого
	}

	for k := 0; k < N; k++ {
		if logScaled[k] {
			v.X[k] = float32(math.Log1p(float64(raw[k])))
		} else {
			v.X[k] = raw[k]
		}
	}
}

func b2f(b bool) float32 {
	if b {
		return 1
	}
	return 0
}

func clamp01(x float32) float32 {
	switch {
	case x < 0:
		return 0
	case x > 1:
		return 1
	}
	return x
}
