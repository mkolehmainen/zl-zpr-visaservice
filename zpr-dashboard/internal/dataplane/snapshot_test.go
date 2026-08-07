package dataplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFetchVisaSnapshotFailsOnPartialDetail checks a snapshot whose ID list
// succeeds but whose detail fetch fails is reported as an error rather than a
// silently undercounted visa set.
func TestFetchVisaSnapshotFailsOnPartialDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin/visas":
			w.Write([]byte(`[{"id":1},{"id":2}]`))
		case r.URL.Path == "/admin/authrevoke":
			w.Write([]byte(`[]`))
		case r.URL.Path == "/admin/visas/2":
			w.WriteHeader(http.StatusInternalServerError)
		case strings.HasPrefix(r.URL.Path, "/admin/visas/"):
			w.Write([]byte(`{"id":1}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)

	c := &Client{baseURL: srv.URL, http: srv.Client()}

	snapshot, err := c.FetchVisaSnapshot(context.Background())
	if err == nil {
		t.Fatalf("expected an error, got snapshot with %d visas", len(snapshot.RecentVisas))
	}
	if len(snapshot.RecentVisas) != 0 {
		t.Errorf("expected no partial visas alongside the error, got %d", len(snapshot.RecentVisas))
	}
}

// TestFetchVisaSnapshotDropsGoneVisas checks a visa that disappears between the
// ID listing and its detail fetch is dropped from the snapshot rather than
// failing the whole refresh.
func TestFetchVisaSnapshotDropsGoneVisas(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin/visas":
			w.Write([]byte(`[{"id":1},{"id":2}]`))
		case r.URL.Path == "/admin/authrevoke":
			w.Write([]byte(`[]`))
		case r.URL.Path == "/admin/visas/2":
			w.WriteHeader(http.StatusNotFound)
		case strings.HasPrefix(r.URL.Path, "/admin/visas/"):
			w.Write([]byte(`{"id":1}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)

	c := &Client{baseURL: srv.URL, http: srv.Client()}

	snapshot, err := c.FetchVisaSnapshot(context.Background())
	if err != nil {
		t.Fatalf("expected a usable snapshot, got error: %v", err)
	}
	if len(snapshot.RecentVisas) != 1 {
		t.Errorf("expected the surviving visa only, got %d", len(snapshot.RecentVisas))
	}
	if snapshot.ActiveCount != 1 {
		t.Errorf("expected ActiveCount to match the fetched visas, got %d", snapshot.ActiveCount)
	}
}
