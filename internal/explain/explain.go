// Package explain превращает разложение модели в список причин для оператора:
// признак, его значение, вклад в лог-шансы и понятная фраза. Оператору бесполезен
// ответ «0,87» — нужны факторы с вкладом, иначе решение нельзя ни отладить, ни защитить.
package explain

import (
	"fmt"
	"math"

	"github.com/sanchyous/redflag-antifraud/internal/features"
	"github.com/sanchyous/redflag-antifraud/internal/scoring"
)

// Reason — одна причина решения.
type Reason struct {
	Factor       string  `json:"factor"`
	Value        float64 `json:"value"`
	Contribution float64 `json:"contribution"`
	Effect       string  `json:"effect"` // "raises" | "lowers"
	Text         string  `json:"text"`
}

// Reasons возвращает причины, повышающие риск (до maxPos, вклад не меньше minContribution),
// и до maxNeg смягчающих. Аллоцирует: вызывать для review/block или по запросу.
func Reasons(ex *scoring.Explanation, minContribution float32, maxPos, maxNeg int) []Reason {
	out := make([]Reason, 0, maxPos+maxNeg)
	for i := 0; i < ex.NPos && i < maxPos; i++ {
		c := ex.Pos[i]
		if c.Contribution < minContribution {
			break
		}
		out = append(out, reason(c, "raises"))
	}
	for i := 0; i < ex.NNeg && i < maxNeg; i++ {
		c := ex.Neg[i]
		if -c.Contribution < minContribution {
			break
		}
		out = append(out, reason(c, "lowers"))
	}
	return out
}

func reason(c scoring.Contribution, effect string) Reason {
	return Reason{
		Factor:       features.Names[c.Feature],
		Value:        round(float64(c.Raw)),
		Contribution: round(float64(c.Contribution)),
		Effect:       effect,
		Text:         Text(int(c.Feature), c.Raw),
	}
}

func round(x float64) float64 { return math.Round(x*1000) / 1000 }

// Text — человекочитаемая фраза для признака с исходным значением.
func Text(feature int, raw float32) string {
	if feature < 0 || feature >= features.N {
		return "неизвестный фактор"
	}
	n := int(math.Round(float64(raw)))
	pct := int(math.Round(float64(raw) * 100))
	switch feature {
	case features.OutCalls1h:
		return fmt.Sprintf("%d исходящих вызовов за час", n)
	case features.OutCalls24h:
		return fmt.Sprintf("%d исходящих вызовов за сутки", n)
	case features.OutPeers1h:
		return fmt.Sprintf("%d разных получателей за час", n)
	case features.OutPeers24h:
		return fmt.Sprintf("%d разных получателей за сутки", n)
	case features.OutNovelty:
		return fmt.Sprintf("%d%% вызовов уходят новым собеседникам", pct)
	case features.OutRegions24h:
		return fmt.Sprintf("охват %d регионов получателей за сутки", n)
	case features.OutRegionEntropy:
		return fmt.Sprintf("равномерный обзвон регионов (энтропия %.1f бит)", raw)
	case features.OutShortShare:
		return fmt.Sprintf("%d%% принятых вызовов короче 10 с", pct)
	case features.OutUnansweredShare:
		return fmt.Sprintf("%d%% вызовов остались без ответа", pct)
	case features.OutGapRobot:
		return fmt.Sprintf("вызовы идут с машинной регулярностью (индекс %.2f)", raw)
	case features.InCalls1h:
		return fmt.Sprintf("получателю поступило %d вызовов за час", n)
	case features.InPeers24h:
		return fmt.Sprintf("получателю звонили %d разных номеров за сутки", n)
	case features.CallShort:
		return "вызов принят и завершён меньше чем за 10 с"
	case features.CallHangup1s:
		return "отбой на первой секунде"
	case features.CallUnanswered:
		return "вызов не отвечен"
	case features.CallNight:
		return "ночное время суток"
	case features.CallDuration:
		return fmt.Sprintf("длительность разговора %d с", n)
	case features.ForeignIngress:
		return "вход из-за рубежа"
	case features.Spoof:
		return "российский номер при иностранном входе: подмена номера"
	case features.CallerUnallocated:
		return "номер вызывающего из нераспределённого диапазона"
	case features.CallerInvalid:
		return "номер вызывающего скрыт или некорректен"
	case features.OperatorMismatch:
		return "оператор в сигнализации не совпадает с держателем диапазона"
	case features.ConnInternational:
		return "международный транзит"
	case features.FanMember:
		return "номер входит в веер: группу с общим шаблоном и непересекающимися списками получателей"
	case features.FanSize:
		return fmt.Sprintf("размер веера: %d номеров", n)
	case features.SubscriberNumbers:
		return fmt.Sprintf("на того же абонента оформлено ещё %d номеров", n)
	}
	return features.Names[feature]
}
