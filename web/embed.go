// Package web содержит встроенную панель мониторинга (статические файлы без сборки и внешних зависимостей).
// Файлы вкомпилированы в бинарь ядра и отдаются по /ui/.
package web

import "embed"

// FS — файлы панели: index.html, css/, js/, fonts/.
//
//go:embed index.html css js fonts
var FS embed.FS

// StackMap — отдельная статическая страница с картой стека и инфраструктуры, отдаётся по /stack-map
// (не через FS/uiHandler: это не часть SPA-панели, а самостоятельная страница).
//
//go:embed stack-map.html
var StackMap embed.FS
