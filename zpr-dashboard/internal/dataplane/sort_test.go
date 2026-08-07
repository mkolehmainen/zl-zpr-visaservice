package dataplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGetActorSortsAttrs checks attributes come back sorted by key, so views
// can render them without sorting on every frame.
func TestGetActorSortsAttrs(t *testing.T) {
	c := testClient(t, `{"cn":"adapter-a","attrs":[
		{"key":"user.hair_color","value":["brown"]},
		{"key":"zpr.role","value":["adapter"]},
		{"key":"org.team","value":["infra"]}
	]}`)

	actor, err := c.GetActor(context.Background(), "adapter-a")
	if err != nil {
		t.Fatalf("GetActor: %v", err)
	}

	want := []string{"org.team", "user.hair_color", "zpr.role"}
	if len(actor.Attrs) != len(want) {
		t.Fatalf("got %d attrs, want %d", len(actor.Attrs), len(want))
	}
	for i, key := range want {
		if actor.Attrs[i].Key != key {
			t.Errorf("attr %d = %q, want %q", i, actor.Attrs[i].Key, key)
		}
	}
}

// TestFetchActorVisasSortsByIDDesc checks visa lists come back newest-ID
// first, the canonical order every visa table renders in.
func TestFetchActorVisasSortsByIDDesc(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := strings.CutPrefix(r.URL.Path, "/admin/visas/"); ok {
			w.Write([]byte(`{"id":` + id + `}`))
			return
		}
		w.Write([]byte(`[{"id":3},{"id":7},{"id":2}]`))
	}))
	t.Cleanup(srv.Close)

	c := &Client{baseURL: srv.URL, http: srv.Client()}

	visas, err := c.FetchActorVisas(context.Background(), "adapter-a")
	if err != nil {
		t.Fatalf("FetchActorVisas: %v", err)
	}

	want := []int64{7, 3, 2}
	if len(visas) != len(want) {
		t.Fatalf("got %d visas, want %d", len(visas), len(want))
	}
	for i, id := range want {
		if visas[i].ID != id {
			t.Errorf("visa %d = %d, want %d", i, visas[i].ID, id)
		}
	}
}

// TestFetchServicesSortsByName checks services come back sorted by name
// regardless of the order the admin API lists them in.
func TestFetchServicesSortsByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if name, ok := strings.CutPrefix(r.URL.Path, "/admin/services/"); ok {
			w.Write([]byte(`{"service_name":"` + name + `"}`))
			return
		}
		w.Write([]byte(`[{"id":"zebra"},{"id":"alpha"},{"id":"middle"}]`))
	}))
	t.Cleanup(srv.Close)

	c := &Client{baseURL: srv.URL, http: srv.Client()}

	services, err := c.FetchServices(context.Background())
	if err != nil {
		t.Fatalf("FetchServices: %v", err)
	}

	want := []string{"alpha", "middle", "zebra"}
	if len(services) != len(want) {
		t.Fatalf("got %d services, want %d", len(services), len(want))
	}
	for i, name := range want {
		if services[i].ServiceName != name {
			t.Errorf("service %d = %q, want %q", i, services[i].ServiceName, name)
		}
	}
}
