package enrich

import "strings"

// Brand — крупный оператор, к которому приводятся и записи реестра (по ИНН),
// и названия из сигнализации (по подстроке).
type Brand uint8

const (
	BrandUnknown Brand = iota
	BrandMTS
	BrandMegaFon
	BrandBeeline
	BrandTele2
	BrandRostelecom
)

var brandNames = [...]string{"", "МТС", "МегаФон", "Билайн", "Т2", "Ростелеком"}

func (b Brand) String() string {
	if int(b) < len(brandNames) {
		return brandNames[b]
	}
	return ""
}

// brandByINN — ИНН юридических лиц крупных операторов.
func brandByINN(inn string) Brand {
	switch inn {
	case "7740000076":
		return BrandMTS
	case "7812014560":
		return BrandMegaFon
	case "7713076301":
		return BrandBeeline
	case "7743895280":
		return BrandTele2
	case "7707049388":
		return BrandRostelecom
	}
	return BrandUnknown
}

// brandByName распознаёт название оператора из сигнализации ("MTS", "ПАО МегаФон", "Tele2" ...).
func brandByName(name string) Brand {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return BrandUnknown
	}
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(n, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("мтс", "mts", "мобильные телесистемы"):
		return BrandMTS
	case has("мегафон", "megafon"):
		return BrandMegaFon
	case has("билайн", "beeline", "вымпелком", "vimpelcom"):
		return BrandBeeline
	case has("теле2", "tele2", "т2 мобайл", "t2 mobile"):
		return BrandTele2
	case has("ростелеком", "rostelecom"):
		return BrandRostelecom
	}
	return BrandUnknown
}
