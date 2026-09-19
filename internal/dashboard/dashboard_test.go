package dashboard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wang110696/Leash/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	return rec.Code, string(body)
}

func TestSessionsHandler_Empty(t *testing.T) {
	h := New(testStore(t))
	code, body := get(t, h, "/")
	if code != http.StatusOK {
		t.Fatalf("status = %d; want 200", code)
	}
	if !strings.Contains(body, "No sessions recorded yet") {
		t.Fatalf("body missing empty-state message: %s", body)
	}
}

func TestSessionsHandler_ListsSessions(t *testing.T) {
	st := testStore(t)
	if err := st.InsertEvent("sess-abc", "network", "info", store.Allow, map[string]any{"host": "example.com"}); err != nil {
		t.Fatal(err)
	}
	h := New(st)

	code, body := get(t, h, "/")
	if code != http.StatusOK {
		t.Fatalf("status = %d; want 200", code)
	}
	if !strings.Contains(body, "sess-abc") {
		t.Fatalf("body missing session id: %s", body)
	}
	if !strings.Contains(body, `href="/session/sess-abc"`) {
		t.Fatalf("body missing link to session detail: %s", body)
	}
}

func TestSessionHandler_ShowsEvents(t *testing.T) {
	st := testStore(t)
	if err := st.InsertEvent("sess-1", "network", "high", store.Block,
		map[string]any{"host": "evil.example", "matched_rules": []string{"dotenv_pattern"}}); err != nil {
		t.Fatal(err)
	}
	h := New(st)

	code, body := get(t, h, "/session/sess-1")
	if code != http.StatusOK {
		t.Fatalf("status = %d; want 200", code)
	}
	if !strings.Contains(body, "evil.example") {
		t.Fatalf("body missing event field value: %s", body)
	}
	if !strings.Contains(body, "badge-block") {
		t.Fatalf("body missing block badge class: %s", body)
	}
}

func TestSessionHandler_UnknownSessionShowsEmptyState(t *testing.T) {
	h := New(testStore(t))
	code, body := get(t, h, "/session/does-not-exist")
	if code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (empty timeline, not an error)", code)
	}
	if !strings.Contains(body, "No events recorded") {
		t.Fatalf("body missing empty-state message: %s", body)
	}
}

func TestSessionHandler_RejectsPathTraversal(t *testing.T) {
	h := New(testStore(t))
	code, _ := get(t, h, "/session/../etc/passwd")
	if code == http.StatusOK {
		t.Fatalf("status = %d; want not-OK for a session id containing a path separator", code)
	}
}

// TestSessionsHandler_EscapesUntrustedContent verifies event field values
// (which can contain agent-influenced strings, e.g. a Host header) are
// HTML-escaped rather than rendered raw. html/template does this
// automatically; this test exists to catch a regression if the templates
// are ever changed to bypass it (e.g. via template.HTML).
func TestSessionHandler_EscapesUntrustedContent(t *testing.T) {
	st := testStore(t)
	if err := st.InsertEvent("sess-xss", "network", "info", store.Allow,
		map[string]any{"host": `<script>alert(1)</script>`}); err != nil {
		t.Fatal(err)
	}
	h := New(st)

	_, body := get(t, h, "/session/sess-xss")
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("unescaped script tag found in rendered output — XSS risk: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("expected HTML-escaped form of the value in output: %s", body)
	}
}

func TestDashboardServesRealHTTPServer(t *testing.T) {
	st := testStore(t)
	if err := st.InsertEvent("sess-live", "network", "info", store.Allow, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d; want 200", resp.StatusCode)
	}
}

func TestSessionHandler_MultilineFieldRendersAsPre(t *testing.T) {
	st := testStore(t)
	if err := st.InsertEvent("sess-diff", "git_diff_stat", "info", store.Allow,
		map[string]any{"remote": "github.com/known/repo", "stat": "README.md | 2 +-\n1 file changed, 1 insertion(+), 1 deletion(-)"}); err != nil {
		t.Fatal(err)
	}
	h := New(st)

	_, body := get(t, h, "/session/sess-diff")
	if !strings.Contains(body, "<pre>README.md") {
		t.Fatalf("expected multiline stat field to render inside <pre>: %s", body)
	}
}
