// Package docsui — страница Swagger UI для /docs, вкомпилированная в бинарь (swagger-ui-dist@5.33.1,
// Apache-2.0: https://github.com/swagger-api/swagger-ui). Раньше CSS/JS грузились с unpkg.com — без
// интернета (закрытый контур, в котором и заявлен весь остальной сервис) страница не открывалась.
package docsui

import "embed"

//go:embed index.html swagger-ui.css swagger-ui-bundle.js favicon-32x32.png
var FS embed.FS
