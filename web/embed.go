// Package web содержит встроенную панель мониторинга (статические файлы без сборки и внешних зависимостей).
// Файлы вкомпилированы в бинарь ядра и отдаются по /ui/.
package web

import "embed"

// FS — файлы панели: index.html, css/, js/, fonts/.
//
//go:embed index.html css js fonts
var FS embed.FS
