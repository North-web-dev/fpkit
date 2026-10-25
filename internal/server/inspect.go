package server

import (
	"encoding/json"
	"net/http"

	"github.com/North-web-dev/fpkit/data"
	"github.com/North-web-dev/fpkit/internal/web"
)

// InspectConfig configures the reflector server.
type InspectConfig struct {
	Addr    string
	TLSCert string
	TLSKey  string
}

// RunInspect starts the reflector: a web UI plus GET /api/all that report the
// calling client's own JA4/JA4H/Akamai-H2.
func RunInspect(cfg InspectConfig) error {
	db, err := data.Load()
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/_fp/app.css", web.CSSHandler)
	mux.HandleFunc("/db", web.PageHandler("db.html"))
	mux.HandleFunc("/api/all", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, gather(db, r))
	})
	registerDBAPI(mux, db)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		web.PageHandler("inspect.html")(w, r)
	})

	return serveTLS("inspect", cfg.Addr, cfg.TLSCert, cfg.TLSKey, mux)
}

// registerDBAPI wires the reverse-lookup JSON API shared by inspect/hook UIs.
func registerDBAPI(mux *http.ServeMux, db *data.DB) {
	mux.HandleFunc("/api/db/list", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, db)
	})
	mux.HandleFunc("/api/db/ja4/{value}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, db.Classify(r.PathValue("value")))
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
