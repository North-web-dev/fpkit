// Package web embeds the self-contained UI served by fp inspect and fp hook.
package web

import (
	"embed"
	"net/http"
)

//go:embed assets
var assets embed.FS

// File returns an embedded asset's bytes.
func File(name string) ([]byte, error) {
	return assets.ReadFile("assets/" + name)
}

// CSSHandler serves the shared stylesheet at /_fp/app.css.
func CSSHandler(w http.ResponseWriter, r *http.Request) {
	b, err := File("app.css")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write(b)
}

// PageHandler serves one embedded HTML page.
func PageHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := File(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	}
}
