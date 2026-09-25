package api

import (
	"embed"
	"net/http"
)

//go:embed openapi.yaml
var openapiFS embed.FS

const docsHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>RedFlag Decision API</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({ url: "/openapi.yaml", dom_id: "#swagger" });
  </script>
</body>
</html>`

func (s *Server) handleDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(docsHTML))
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
