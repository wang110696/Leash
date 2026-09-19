// Package dashboard implements the v0.3 "Flight Recorder" local web UI
// (ARCHITECTURE.md 10.1): a session list and a per-session chronological
// event timeline (including the git diff --stat "diff viewer" and process
// events from earlier in v0.3/v0.2), served over plain server-rendered
// HTML — no JS framework, no CDN dependency, consistent with the project's
// offline-first, no-external-dependency stance for a security tool.
//
// It's read-only and binds to 127.0.0.1 only (see cmd/leash: New's caller
// picks the listener) — this views what Leash has already recorded, it
// doesn't accept input.
package dashboard

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"

	"github.com/wang110696/Leash/internal/store"
)

// New returns the dashboard's http.Handler.
func New(st *store.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", sessionsHandler(st))
	mux.HandleFunc("/session/", sessionHandler(st))
	return mux
}

func sessionsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		sessions, err := st.ListSessions()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := sessionsTmpl.Execute(w, sessions); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func sessionHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/session/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		events, err := st.ListEvents(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		view := make([]eventView, len(events))
		for i, e := range events {
			view[i] = toEventView(e)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := sessionTmpl.Execute(w, struct {
			SessionID string
			Events    []eventView
		}{id, view}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// eventView flattens a store.Event's payload into sorted key/value pairs
// for straightforward, uniform template rendering regardless of kind — the
// dashboard doesn't need a special-cased renderer per event kind, just a
// generic "here's what we recorded" view. Multi-line values (currently
// just git_diff_stat's "stat" field) render preformatted.
type eventView struct {
	store.Event
	Fields []fieldView
}

type fieldView struct {
	Key       string
	Value     string
	Multiline bool
}

func toEventView(e store.Event) eventView {
	var payload map[string]any
	_ = json.Unmarshal([]byte(e.PayloadJSON), &payload) // best-effort; empty Fields on failure

	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fields := make([]fieldView, 0, len(keys))
	for _, k := range keys {
		v := fmt.Sprintf("%v", payload[k])
		fields = append(fields, fieldView{Key: k, Value: v, Multiline: strings.Contains(v, "\n")})
	}

	return eventView{Event: e, Fields: fields}
}

const baseCSS = `
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; }
h1, h2 { font-weight: 600; }
table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #e0e0e0; }
th { color: #666; font-size: 0.85rem; text-transform: uppercase; }
a { color: #0060df; text-decoration: none; }
a:hover { text-decoration: underline; }
.badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
.badge-allow { background: #e3f9e5; color: #1b7a2c; }
.badge-warn  { background: #fff4d6; color: #8a6100; }
.badge-block { background: #fde3e3; color: #a11212; }
.kind { font-family: ui-monospace, monospace; font-size: 0.85rem; color: #444; }
.fields { font-family: ui-monospace, monospace; font-size: 0.85rem; color: #333; }
.fields div { margin: 0.15rem 0; }
.fields pre { background: #fff; border: 1px solid #e0e0e0; border-radius: 4px; padding: 0.5rem; overflow-x: auto; margin: 0.25rem 0; }
.ts { color: #888; font-size: 0.85rem; white-space: nowrap; }
`

var funcs = template.FuncMap{
	"badgeClass": func(d store.Decision) string {
		switch d {
		case store.Block:
			return "badge-block"
		case store.Warn:
			return "badge-warn"
		default:
			return "badge-allow"
		}
	},
}

var sessionsTmpl = template.Must(template.New("sessions").Funcs(funcs).Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Leash — Sessions</title><style>` + baseCSS + `</style></head>
<body>
<h1>🦮 Leash — Sessions</h1>
{{if not .}}<p>No sessions recorded yet.</p>{{end}}
<table>
<tr><th>Session</th><th>Started</th><th>Events</th><th>Allow</th><th>Warn</th><th>Block</th></tr>
{{range .}}
<tr>
  <td><a href="/session/{{.SessionID}}">{{.SessionID}}</a></td>
  <td class="ts">{{.StartedAt.Format "2006-01-02 15:04:05"}}</td>
  <td>{{.EventCount}}</td>
  <td>{{.Allow}}</td>
  <td>{{.Warn}}</td>
  <td>{{.Block}}</td>
</tr>
{{end}}
</table>
</body></html>
`))

var sessionTmpl = template.Must(template.New("session").Funcs(funcs).Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Leash — Session {{.SessionID}}</title><style>` + baseCSS + `</style></head>
<body>
<p><a href="/">&larr; all sessions</a></p>
<h1>Session {{.SessionID}}</h1>
{{if not .Events}}<p>No events recorded for this session.</p>{{end}}
<table>
<tr><th>Time</th><th>Kind</th><th>Decision</th><th>Details</th></tr>
{{range .Events}}
<tr>
  <td class="ts">{{.Ts.Format "15:04:05.000"}}</td>
  <td class="kind">{{.Kind}}</td>
  <td><span class="badge {{badgeClass .Decision}}">{{.Decision}}</span></td>
  <td class="fields">
    {{range .Fields}}
      {{if .Multiline}}<div><strong>{{.Key}}:</strong><pre>{{.Value}}</pre></div>
      {{else}}<div><strong>{{.Key}}:</strong> {{.Value}}</div>{{end}}
    {{end}}
  </td>
</tr>
{{end}}
</table>
</body></html>
`))
