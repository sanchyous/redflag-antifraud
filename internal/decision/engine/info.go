package engine

import (
	"strconv"

	"github.com/sanchyous/redflag-antifraud/internal/decision/mlclient"
	"github.com/sanchyous/redflag-antifraud/internal/detection/features"
	"github.com/sanchyous/redflag-antifraud/internal/telecom/phone"
)

// Info — сводка состояния движка для панели мониторинга. Секретов не содержит.
type Info struct {
	Stage1 struct {
		Version string  `json:"version"`
		Review  float32 `json:"review"`
		Block   float32 `json:"block"`
	} `json:"stage1"`
	Policy struct {
		Review     float32 `json:"review"`
		Block      float32 `json:"block"`
		MinSignals int     `json:"min_signals"`
	} `json:"policy"`
	ML struct {
		Enabled     bool    `json:"enabled"`
		Active      bool    `json:"active"`
		Version     string  `json:"version"`
		Gate        float32 `json:"gate"`
		Review      float32 `json:"review"`
		Block       float32 `json:"block"`
		BreakerOpen bool    `json:"breaker_open"`
	} `json:"ml"`
	TrackedNumbers int `json:"tracked_numbers"`
	Fan            struct {
		Groups  int `json:"groups"`
		Members int `json:"members"`
	} `json:"fan"`
	Numplan struct {
		Enabled bool   `json:"enabled"`
		Version string `json:"version"`
		Ranges  int    `json:"ranges"`
		Regions int    `json:"regions"`
	} `json:"numplan"`
	Protect struct {
		Allowlist int `json:"allowlist"`
	} `json:"protect"`
}

// Info возвращает сводку состояния движка.
func (e *Engine) Info() Info {
	var in Info
	m, p := e.model.Load(), e.policy.Load()
	in.Stage1.Version, in.Stage1.Review, in.Stage1.Block = m.Version, m.Review, m.Block
	in.Policy.Review, in.Policy.Block, in.Policy.MinSignals = p.Review, p.Block, p.MinStrong
	in.ML.Enabled = e.cfg.ML != nil
	if st := e.ml.Load(); st != nil {
		in.ML.Active, in.ML.Version, in.ML.Gate = true, st.Version, st.Gate
		in.ML.Review, in.ML.Block = st.Policy.Review, st.Policy.Block
	}
	if e.cfg.ML != nil {
		in.ML.BreakerOpen = e.cfg.ML.Open()
	}
	in.TrackedNumbers = e.win.Len()
	if fan := e.fan.Index(); fan != nil {
		in.Fan.Groups, in.Fan.Members = fan.Groups(), fan.Members()
	}
	if e.cfg.Plan != nil {
		in.Numplan.Enabled, in.Numplan.Version = true, e.cfg.Plan.Version
		in.Numplan.Ranges, in.Numplan.Regions = e.cfg.Plan.Size(), e.cfg.Plan.RegionCount()
	}
	in.Protect.Allowlist = e.class.Size()
	return in
}

// FeatureWeight — признак линейной модели: вес и значение эталонного абонента.
type FeatureWeight struct {
	Name string  `json:"name"`
	W    float32 `json:"w"`
	Base float32 `json:"base"`
}

// ModelView — описание моделей для панели: веса стадии 1 и параметры ML.
type ModelView struct {
	Stage1 struct {
		Version    string             `json:"version"`
		Bias       float32            `json:"bias"`
		Features   []FeatureWeight    `json:"features"`
		Thresholds map[string]float32 `json:"thresholds"`
	} `json:"stage1"`
	MinSignals int            `json:"min_signals"`
	ML         *mlclient.Info `json:"ml"`
}

// ModelView возвращает описание моделей.
func (e *Engine) ModelView() ModelView {
	var v ModelView
	m := e.model.Load()
	v.Stage1.Version, v.Stage1.Bias = m.Version, m.Bias
	v.Stage1.Thresholds = map[string]float32{"review": m.Review, "block": m.Block}
	for i, n := range features.Names {
		v.Stage1.Features = append(v.Stage1.Features, FeatureWeight{Name: n, W: m.W[i], Base: m.Base[i]})
	}
	v.MinSignals = e.policy.Load().MinStrong
	if st := e.ml.Load(); st != nil {
		inf := st.Info
		v.ML = &inf
	}
	return v
}

// FanMember — участник веера для панели: номера только в маскированном виде.
type FanMember struct {
	Number    string   `json:"number"`
	Calls     uint32   `json:"calls"`
	PeerCount int      `json:"peer_count"`
	Peers     []string `json:"peers"`
}

// FanGroup — найденный веер для панели.
type FanGroup struct {
	ID       string      `json:"id"`
	Label    string      `json:"label"`
	Size     int         `json:"size"`
	Disjoint float32     `json:"disjoint"`
	Calls    uint32      `json:"calls"`
	Members  []FanMember `json:"members"`
}

// FanGroups возвращает найденные веера (крупные первыми).
func (e *Engine) FanGroups() []FanGroup {
	groups := e.fan.Index().List()
	out := make([]FanGroup, 0, len(groups))
	for _, g := range groups {
		fg := FanGroup{ID: strconv.FormatUint(g.ID, 10), Label: maskKey(g.ID), Size: g.Size, Disjoint: g.Disjoint, Calls: g.Calls}
		for _, m := range g.Members {
			fm := FanMember{Number: maskKey(m.Key), Calls: m.Calls, PeerCount: m.PeerCount}
			for _, p := range m.PeersSample {
				fm.Peers = append(fm.Peers, maskKey(p))
			}
			fg.Members = append(fg.Members, fm)
		}
		out = append(out, fg)
	}
	return out
}

// maskKey восстанавливает маскированный номер из ключа phone.Number.Key(): только полные номера
// (у коротких и маскированных ключ необратим).
func maskKey(k uint64) string {
	const classBits = uint64(3) << 62
	if k == 0 || k&classBits != 0 {
		return "***"
	}
	n, err := phone.Parse("+" + strconv.FormatUint(k, 10))
	if err != nil {
		return "***"
	}
	return n.Mask()
}
