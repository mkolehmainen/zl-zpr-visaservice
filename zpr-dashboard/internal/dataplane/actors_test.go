package dataplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// actorListBody is a GET /admin/actors response as the address-keyed admin API
// serves it: the address identifies the actor, the CN may be null.
const actorListBody = `[{"zpr_addr":"fd5a:5052::1","cn":null},{"zpr_addr":"fd5a:5052::2","cn":"node-a"}]`

// TestListActorsDecodesAddressKeyedEntries pins the two-field ActorEntry
// shape: the address is required, the CN is optional (empty when null), and
// the phantom fields the old CnEntry carried are gone.
func TestListActorsDecodesAddressKeyedEntries(t *testing.T) {
	c := testClient(t, actorListBody)

	entries, err := c.ListActors(context.Background())
	if err != nil {
		t.Fatalf("ListActors: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].ZprAddress != "fd5a:5052::1" || entries[0].CName != "" {
		t.Errorf("entry 0 = %+v, want address fd5a:5052::1 with no CN", entries[0])
	}
	if entries[1].ZprAddress != "fd5a:5052::2" || entries[1].CName != "node-a" {
		t.Errorf("entry 1 = %+v, want address fd5a:5052::2 with CN node-a", entries[1])
	}

	// The wire shape is {zpr_addr, cn} and nothing else; the old CnEntry's
	// five phantom fields always decoded to zero values.
	typ := reflect.TypeOf(entries[0])
	if typ.Name() != "ActorEntry" {
		t.Errorf("list entry type = %s, want ActorEntry", typ.Name())
	}
	if typ.NumField() != 2 {
		t.Errorf("list entry has %d fields, want 2 (zpr_addr, cn)", typ.NumField())
	}
}

// actorAPIServer serves the address-keyed admin actor API and records every
// path it is asked for. Detail lookups answer only under /admin/actors/{addr}
// — a CN in the path is a miss, exactly like the real A2 handlers.
func actorAPIServer(t *testing.T) (*Client, *[]string) {
	t.Helper()

	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)

		switch r.URL.Path {
		case "/admin/actors":
			w.Write([]byte(actorListBody))
		case "/admin/actors/fd5a:5052::1":
			json.NewEncoder(w).Encode(map[string]any{"zpr_addr": "fd5a:5052::1", "cn": nil, "ident": "oidc-only"})
		case "/admin/actors/fd5a:5052::2":
			json.NewEncoder(w).Encode(map[string]any{"zpr_addr": "fd5a:5052::2", "cn": "node-a", "ident": "certified"})
		default:
			// The A2 handlers parse the segment as an address; a CN is a 400.
			http.Error(w, "bad request", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	return &Client{baseURL: srv.URL, http: srv.Client()}, &paths
}

// TestFetchActorsJoinsOnAddress checks the list→detail join keys on the ZPR
// address, so a CN-less actor still gets its full descriptor, and the IPv6
// literal reaches the server as a clean path segment.
func TestFetchActorsJoinsOnAddress(t *testing.T) {
	c, paths := actorAPIServer(t)

	actors, err := c.FetchActors(context.Background())
	if err != nil {
		t.Fatalf("FetchActors: %v", err)
	}

	if len(actors) != 2 {
		t.Fatalf("got %d actors, want 2", len(actors))
	}
	if actors[0].ZprAddress != "fd5a:5052::1" || actors[0].Ident != "oidc-only" {
		t.Errorf("actor 0 = %+v, want the CN-less actor's full descriptor", actors[0])
	}
	if actors[1].CName != "node-a" || actors[1].Ident != "certified" {
		t.Errorf("actor 1 = %+v, want node-a's full descriptor", actors[1])
	}

	for _, want := range []string{"/admin/actors/fd5a:5052::1", "/admin/actors/fd5a:5052::2"} {
		found := false
		for _, p := range *paths {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("detail fetch for %s missing; paths requested: %v", want, *paths)
		}
	}
}

// TestFetchActorsDegradedFallbackKeepsAddress checks an actor whose detail
// lookup fails is kept as an address-keyed stub — the address is always on the
// list entry, so the degraded row can still be selected and labelled.
func TestFetchActorsDegradedFallbackKeepsAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/actors" {
			w.Write([]byte(actorListBody))
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := &Client{baseURL: srv.URL, http: srv.Client()}

	actors, err := c.FetchActors(context.Background())
	if err != nil {
		t.Fatalf("FetchActors: %v", err)
	}

	if len(actors) != 2 {
		t.Fatalf("got %d actors, want 2", len(actors))
	}
	if actors[0].ZprAddress != "fd5a:5052::1" || actors[0].CName != "" {
		t.Errorf("degraded actor 0 = %+v, want address-keyed stub", actors[0])
	}
	if actors[1].ZprAddress != "fd5a:5052::2" || actors[1].CName != "node-a" {
		t.Errorf("degraded actor 1 = %+v, want address plus CN", actors[1])
	}
}

// TestFetchNodesJoinsOnAddress checks the node list→detail join also keys on
// the address.
func TestFetchNodesJoinsOnAddress(t *testing.T) {
	c, _ := actorAPIServer(t)

	nodes, err := c.FetchNodes(context.Background())
	if err != nil {
		t.Fatalf("FetchNodes: %v", err)
	}

	if len(nodes) != 2 {
		t.Fatalf("got %d nodes, want 2 — a CN-keyed detail fetch 400s and drops rows", len(nodes))
	}
}

// TestVisaListPathsUseAddress checks both visa listings build their URL from
// the ZPR address, IPv6 colons intact.
func TestVisaListPathsUseAddress(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)

	c := &Client{baseURL: srv.URL, http: srv.Client()}

	if _, err := c.ListActorVisas(context.Background(), "fd5a:5052::1"); err != nil {
		t.Fatalf("ListActorVisas: %v", err)
	}
	if _, err := c.ListNodeVisas(context.Background(), "fd5a:5052::1"); err != nil {
		t.Fatalf("ListNodeVisas: %v", err)
	}

	want := []string{"/admin/actors/fd5a:5052::1/visas", "/admin/nodes/fd5a:5052::1/visas"}
	if len(paths) != len(want) || paths[0] != want[0] || paths[1] != want[1] {
		t.Errorf("visa paths = %v, want %v", paths, want)
	}
}
