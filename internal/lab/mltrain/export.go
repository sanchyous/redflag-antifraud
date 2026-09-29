package mltrain

import (
	"encoding/csv"
	"io"
	"strconv"

	"github.com/sanchyous/redflag-antifraud/internal/detection/features"
)

// ExportColumns возвращает заголовок CSV: служебные поля, затем r_<признак> (исходные значения)
// и x_<признак> (вход линейной модели). Порядок и имена — контракт с Python-сервисом.
func ExportColumns() []string {
	cols := []string{"label", "kind", "class", "signals", "emergency", "caller", "ts", "s1"}
	for _, n := range features.Names {
		cols = append(cols, "r_"+n)
	}
	for _, n := range features.Names {
		cols = append(cols, "x_"+n)
	}
	return cols
}

// ExportCSV пишет строки в CSV. Экстренные вызовы попадают с флагом emergency=1 и нулевыми
// признаками (их не обучают: защитный слой стоит выше модели).
func ExportCSV(w io.Writer, rows []Row) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(ExportColumns()); err != nil {
		return err
	}
	rec := make([]string, 0, 8+2*features.N)
	b2s := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	f32 := func(v float32) string { return strconv.FormatFloat(float64(v), 'g', -1, 32) }
	for i := range rows {
		r := &rows[i]
		rec = append(rec[:0], b2s(r.Label), string(r.Kind), strconv.Itoa(int(r.Class)),
			strconv.Itoa(int(r.Signals)), b2s(r.Emergency), r.Caller, strconv.FormatInt(r.TS, 10), f32(r.Score1))
		for k := 0; k < features.N; k++ {
			rec = append(rec, f32(r.Raw[k]))
		}
		for k := 0; k < features.N; k++ {
			rec = append(rec, f32(r.X[k]))
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
