// Package numplan — офлайн-справочник российского плана нумерации (реестр Россвязи,
// файлы ABC-3xx/4xx/8xx и DEF-9xx): по номеру возвращает оператора-держателя диапазона
// и регион. Внешних API нет: справочник грузится из CSV один раз при старте, поиск —
// бинарный по отсортированным диапазонам (O(log n)).
//
// Ограничения (важно для интерпретации):
//   - Оператор диапазона — это оператор, которому диапазон выделен. Из-за переносимости
//     номеров (MNP) реальный оператор абонента может отличаться.
//   - Регион — регион закрепления диапазона, а не местоположение абонента.
package numplan

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/sanchyous/redflag-antifraud/internal/telecom/phone"
)

const nationalLen = 10 // код (3) + абонентский номер (7)

// Info — результат поиска.
type Info struct {
	Operator string // "" если в найденных диапазонах операторов несколько
	INN      string
	Region   string // "" если в найденных диапазонах регионов несколько
	NonGeo   bool   // безгеографический диапазон (8-800 и т.п.)

	// RegionID — компактный идентификатор региона (1..N), 0 — регион не определён
	// (не найден или под маской несколько регионов). Для множеств и окон без строк.
	RegionID uint16

	MultiOperator bool // под маской подходят диапазоны разных операторов
	MultiRegion   bool // ...и разных регионов
}

type rng struct {
	from, to uint64 // код*10^7 + абонентский номер
	op       uint32 // индекс в Plan.ops
	reg      uint32 // индекс в Plan.regs
}

type opRec struct{ name, inn string }
type regRec struct {
	name   string
	nonGeo bool
}

// Stats — сводка загрузки (для логов и проверки данных).
type Stats struct {
	Rows     int
	Skipped  int // битые строки
	Overlaps int // пересекающиеся диапазоны (в норме 0)
	Files    int
}

// Plan — загруженный справочник. Безопасен для конкурентного чтения.
type Plan struct {
	ranges  []rng
	ops     []opRec
	regs    []regRec
	Version string // короткий хэш содержимого файлов
	Stats   Stats
	smp     sampler
}

// Builder накапливает строки из одного или нескольких CSV.
type Builder struct {
	ranges []rng
	ops    []opRec
	regs   []regRec
	opIdx  map[opRec]uint32
	regIdx map[regRec]uint32
	stats  Stats
	hash   [][]byte
}

// NewBuilder создаёт пустой билдер.
func NewBuilder() *Builder {
	return &Builder{opIdx: map[opRec]uint32{}, regIdx: map[regRec]uint32{}}
}

// AddCSV читает один файл реестра. Формат: UTF-8 (возможен BOM), разделитель ';',
// первая строка — заголовок, поля: код;От;До;Емкость;Оператор;Регион;Территория ГАР;ИНН.
func (b *Builder) AddCSV(r io.Reader) error {
	h := sha256.New()
	br := bufio.NewReaderSize(io.TeeReader(r, h), 1<<20)
	if bom, err := br.Peek(3); err == nil && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF {
		_, _ = br.Discard(3)
	}
	cr := csv.NewReader(br)
	cr.Comma = ';'
	cr.LazyQuotes = true // в названиях операторов встречаются неэкранированные кавычки
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true

	first := true
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				b.stats.Skipped++
				continue
			}
			return fmt.Errorf("numplan: read csv: %w", err)
		}
		if first {
			first = false
			if len(rec) > 0 && !isDigits(strings.TrimSpace(rec[0])) {
				continue // заголовок
			}
		}
		if !b.addRecord(rec) {
			b.stats.Skipped++
		}
	}
	b.stats.Files++
	b.hash = append(b.hash, h.Sum(nil))
	return nil
}

func (b *Builder) addRecord(rec []string) bool {
	if len(rec) < 8 {
		return false
	}
	code := strings.TrimSpace(rec[0])
	from := strings.TrimSpace(rec[1])
	to := strings.TrimSpace(rec[2])
	if len(code) != 3 || len(from) != 7 || len(to) != 7 || !isDigits(code) || !isDigits(from) || !isDigits(to) {
		return false
	}
	c, _ := strconv.ParseUint(code, 10, 64)
	f, _ := strconv.ParseUint(from, 10, 64)
	t, _ := strconv.ParseUint(to, 10, 64)
	if t < f {
		return false
	}
	region, nonGeo := normRegion(rec[5], rec[6])
	op := opRec{name: strings.TrimSpace(rec[4]), inn: strings.TrimSpace(rec[7])}
	oi, ok := b.opIdx[op]
	if !ok {
		oi = uint32(len(b.ops))
		b.ops = append(b.ops, op)
		b.opIdx[op] = oi
	}
	rr := regRec{name: region, nonGeo: nonGeo}
	ri, ok := b.regIdx[rr]
	if !ok {
		ri = uint32(len(b.regs))
		b.regs = append(b.regs, rr)
		b.regIdx[rr] = ri
	}
	const base = 10_000_000
	b.ranges = append(b.ranges, rng{from: c*base + f, to: c*base + t, op: oi, reg: ri})
	return true
}

// Build сортирует диапазоны и возвращает готовый справочник.
func (b *Builder) Build() (*Plan, error) {
	if len(b.ranges) == 0 {
		return nil, errors.New("numplan: no ranges loaded")
	}
	sort.Slice(b.ranges, func(i, j int) bool { return b.ranges[i].from < b.ranges[j].from })
	overlaps := 0
	for i := 1; i < len(b.ranges); i++ {
		if b.ranges[i].from <= b.ranges[i-1].to {
			overlaps++
		}
	}
	b.stats.Rows = len(b.ranges)
	b.stats.Overlaps = overlaps

	h := sha256.New()
	// Порядок файлов не должен влиять на версию.
	sort.Slice(b.hash, func(i, j int) bool { return string(b.hash[i]) < string(b.hash[j]) })
	for _, x := range b.hash {
		h.Write(x)
	}
	return &Plan{
		ranges:  b.ranges,
		ops:     b.ops,
		regs:    b.regs,
		Version: hex.EncodeToString(h.Sum(nil))[:12],
		Stats:   b.stats,
	}, nil
}

// LoadDir загружает все *.csv из каталога.
func LoadDir(dir string) (*Plan, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.csv"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("numplan: no *.csv in %s", dir)
	}
	sort.Strings(files)
	b := NewBuilder()
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		err = b.AddCSV(fh)
		_ = fh.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	return b.Build()
}

// Lookup ищет оператора и регион по номеру. Работает для российских номеров
// (+7 с кодами 3/4/8/9). Для маскированного номера использует известную часть
// префикса: если все подходящие диапазоны принадлежат одному региону/оператору,
// они возвращаются, иначе соответствующее поле пусто и выставлен Multi*.
func (p *Plan) Lookup(n phone.Number) (Info, bool) {
	if !n.IsRU() || len(n.National) != nationalLen {
		return Info{}, false
	}
	known := 0
	for known < nationalLen && n.National[known] != '*' {
		known++
	}
	if known < 3 {
		return Info{}, false
	}
	return p.LookupPrefix(n.National[:known])
}

// LookupPrefix ищет по первым k (3..10) цифрам национальной части.
func (p *Plan) LookupPrefix(prefix string) (Info, bool) {
	k := len(prefix)
	if k < 3 || k > nationalLen || !isDigits(prefix) {
		return Info{}, false
	}
	v, _ := strconv.ParseUint(prefix, 10, 64)
	span := pow10(nationalLen - k)
	lo := v * span
	hi := lo + span - 1

	// первый диапазон, у которого to >= lo (диапазоны не пересекаются → to тоже отсортированы)
	i := sort.Search(len(p.ranges), func(i int) bool { return p.ranges[i].to >= lo })
	var info Info
	found := false
	var op, reg uint32
	for ; i < len(p.ranges) && p.ranges[i].from <= hi; i++ {
		r := p.ranges[i]
		if !found {
			found, op, reg = true, r.op, r.reg
			continue
		}
		if r.op != op && p.ops[r.op] != p.ops[op] {
			info.MultiOperator = true
		}
		if r.reg != reg && p.regs[r.reg] != p.regs[reg] {
			info.MultiRegion = true
		}
	}
	if !found {
		return Info{}, false
	}
	if !info.MultiOperator {
		info.Operator = p.ops[op].name
		info.INN = p.ops[op].inn
	}
	if !info.MultiRegion {
		info.Region = p.regs[reg].name
		info.NonGeo = p.regs[reg].nonGeo
		info.RegionID = uint16(reg + 1)
	}
	return info, true
}

// RegionName возвращает название по идентификатору из Info.RegionID.
func (p *Plan) RegionName(id uint16) string {
	if id == 0 || int(id) > len(p.regs) {
		return ""
	}
	return p.regs[id-1].name
}

// RegionCount — число различных регионов в справочнике.
func (p *Plan) RegionCount() int { return len(p.regs) }

// sampler — индекс для случайного выбора номеров (лениво, для генератора данных).
type sampler struct {
	once     sync.Once
	byRegion [][]int    // индексы диапазонов по региону (индекс = regID)
	cum      [][]uint64 // накопленные размеры диапазонов по региону
	all      []int
	allCum   []uint64
}

func (p *Plan) buildSampler() {
	sm := &p.smp
	sm.byRegion = make([][]int, len(p.regs))
	sm.cum = make([][]uint64, len(p.regs))
	var total uint64
	for i := range p.ranges {
		r := &p.ranges[i]
		if p.regs[r.reg].nonGeo {
			continue
		}
		size := r.to - r.from + 1
		sm.byRegion[r.reg] = append(sm.byRegion[r.reg], i)
		last := uint64(0)
		if n := len(sm.cum[r.reg]); n > 0 {
			last = sm.cum[r.reg][n-1]
		}
		sm.cum[r.reg] = append(sm.cum[r.reg], last+size)
		sm.all = append(sm.all, i)
		total += size
		sm.allCum = append(sm.allCum, total)
	}
}

// RandomNumber возвращает случайный существующий (из распределённых диапазонов) российский номер
// в формате "+7XXXXXXXXXX". regionID != 0 ограничивает выбор регионом (Info.RegionID). Нужен
// генератору синтетических данных; безгеографические диапазоны (8-800) не выбираются.
// Второе значение false — в регионе нет диапазонов.
func (p *Plan) RandomNumber(rnd interface{ Uint64N(uint64) uint64 }, regionID uint16) (string, bool) {
	p.smp.once.Do(p.buildSampler)
	sm := &p.smp
	var idx []int
	var cum []uint64
	if regionID == 0 {
		idx, cum = sm.all, sm.allCum
	} else if int(regionID) <= len(sm.byRegion) {
		idx, cum = sm.byRegion[regionID-1], sm.cum[regionID-1]
	}
	if len(idx) == 0 {
		return "", false
	}
	x := rnd.Uint64N(cum[len(cum)-1])
	k := sort.Search(len(cum), func(i int) bool { return cum[i] > x })
	r := p.ranges[idx[k]]
	before := uint64(0)
	if k > 0 {
		before = cum[k-1]
	}
	v := r.from + (x - before)
	code, num := v/10_000_000, v%10_000_000
	return "+7" + strconv.FormatUint(code, 10) + fmt.Sprintf("%07d", num), true
}

// RegionIDs возвращает идентификаторы всех географических регионов, в которых есть диапазоны.
func (p *Plan) RegionIDs() []uint16 {
	p.smp.once.Do(p.buildSampler)
	var out []uint16
	for i, rs := range p.smp.byRegion {
		if len(rs) > 0 {
			out = append(out, uint16(i+1))
		}
	}
	return out
}

// Size — число диапазонов.
func (p *Plan) Size() int { return len(p.ranges) }

func pow10(n int) uint64 {
	r := uint64(1)
	for ; n > 0; n-- {
		r *= 10
	}
	return r
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// normRegion приводит регион диапазона к субъекту РФ. Поле «Территория ГАР» несёт
// субъект последним сегментом ("г.о. Химки|Московская область"); поле «Регион»
// бывает детальнее ("р-н Красногорский|Московская обл.") или "-". Порядок:
//  1. последний сегмент территории, если это один субъект (без запятой);
//  2. иначе последний сегмент региона (у мобильных: "г. Москва и Московская область");
//  3. иначе то, что есть.
//
// Москва+область и Петербург+Ленобласть сводятся к одному региону: для признака
// «охват регионов» обзвон и Москвы, и области — это не два региона.
func normRegion(region, territory string) (name string, nonGeo bool) {
	if strings.HasPrefix(strings.TrimSpace(region), "Российская Федерация") ||
		strings.HasPrefix(strings.TrimSpace(territory), "Российская Федерация") {
		return "Российская Федерация", true
	}
	r := lastSegment(territory)
	if r == "" || r == "-" || strings.Contains(r, ",") {
		if alt := lastSegment(region); alt != "" && alt != "-" {
			r = alt
		}
	}
	if r == "" || r == "-" {
		return "неизвестно", false
	}
	if strings.HasSuffix(r, " обл.") {
		r = strings.TrimSuffix(r, " обл.") + " область"
	} else if strings.HasSuffix(r, " обл") {
		r = strings.TrimSuffix(r, " обл") + " область"
	}
	if strings.HasPrefix(r, "Город ") {
		r = "г. " + strings.TrimPrefix(r, "Город ")
	}
	if alias, ok := regionAlias[r]; ok {
		r = alias
	}
	return r, false
}

const (
	regMoscow = "Москва и Московская область"
	regSPb    = "Санкт-Петербург и Ленинградская область"
)

var regionAlias = map[string]string{
	"г. Москва":                                  regMoscow,
	"Московская область":                         regMoscow,
	"г. Москва и Московская область":             regMoscow,
	"Город Москва, Московская область":           regMoscow,
	"г. Санкт-Петербург":                         regSPb,
	"Ленинградская область":                      regSPb,
	"г. Санкт-Петербург и Ленинградская область": regSPb,
}

func lastSegment(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '|'); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSpace(s)
}
