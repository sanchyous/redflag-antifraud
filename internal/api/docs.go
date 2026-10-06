package api

import (
	"embed"
	"net/http"

	"github.com/sanchyous/redflag-antifraud/internal/api/docsui"
)

//go:embed openapi.yaml
var openapiFS embed.FS

// mountDocs регистрирует Swagger UI по /docs/ (страница и её ассеты вкомпилированы — см. docsui) и
// спецификацию по /openapi.yaml. /docs без слэша — редирект, как /ui.
func (s *Server) mountDocs(mux *http.ServeMux) {
	files := http.FileServerFS(docsui.FS)
	mux.Handle("GET /docs/", http.StripPrefix("/docs/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		files.ServeHTTP(w, r)
	})))
	mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /openapi.yaml", s.handleOpenAPI)
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	spec, err := openapiFS.ReadFile("openapi.yaml")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "spec_not_found"})
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(spec)
}
