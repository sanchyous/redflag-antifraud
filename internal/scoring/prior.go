package scoring

import "github.com/sanchyous/redflag-antifraud/internal/features"

// Prior — экспертная априорная модель: работает до обучения на данных и служит
// стартовой точкой. Веса заданы из логики домена (см. THEORY.md), эталонный
// абонент — обычный человек с одним-двумя вызовами, разговором около полутора минут; его
// базовые значения намеренно совпадают с «холодным стартом» (нет истории у номера), чтобы
// отсутствие истории не давало отрицательных вкладов и не гасило сильные сигналы вроде подмены.
// Базовый риск эталона — 0,2% (logit ≈ −6,2).
func Prior() *Model {
	m := &Model{Version: "prior-1", Review: 0.15, Block: 0.9}
	set := func(i int, w, base float32) { m.W[i], m.Base[i] = w, base }

	set(features.OutCalls1h, 0.9, 0.69)
	set(features.OutCalls24h, 0.3, 0.69)
	set(features.OutPeers1h, 0.5, 0.69)
	set(features.OutPeers24h, 0.3, 0.69)
	set(features.OutNovelty, 1.5, 0)
	set(features.OutRegions24h, 0.8, 0.7)
	set(features.OutRegionEntropy, 0.35, 0)
	set(features.OutShortShare, 2.0, 0.05)
	set(features.OutUnansweredShare, 1.8, 0.1)
	set(features.OutGapRobot, 1.5, 0)
	set(features.InCalls1h, 0.2, 0.69)
	set(features.InPeers24h, 0.15, 0.69)
	set(features.CallShort, 0.6, 0.05)
	set(features.CallHangup1s, 1.0, 0.01)
	set(features.CallUnanswered, 0.3, 0.2)
	set(features.CallNight, 0.5, 0.05)
	set(features.CallDuration, -0.35, 3.5)
	set(features.ForeignIngress, 0.8, 0.02)
	set(features.Spoof, 3.0, 0)
	set(features.CallerUnallocated, 2.5, 0)
	set(features.CallerInvalid, 1.5, 0.005)
	set(features.OperatorMismatch, 0.7, 0.05)
	set(features.ConnInternational, 0.4, 0.02)
	set(features.FanMember, 2.5, 0)
	set(features.FanSize, 0.3, 0)
	set(features.SubscriberNumbers, 0.9, 0)

	base := -6.2
	for i := 0; i < features.N; i++ {
		base -= float64(m.W[i]) * float64(m.Base[i])
	}
	m.Bias = float32(base)
	return m
}
