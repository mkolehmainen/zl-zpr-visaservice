package dataplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// testClient serves body from a stub server and returns a Client aimed at it.
func testClient(t *testing.T, body string) *Client {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return &Client{baseURL: srv.URL, http: srv.Client()}
}

// TestGetNetworkDecodes checks every displayed field survives the decode,
// including the empty substrate an INVALID link carries.
func TestGetNetworkDecodes(t *testing.T) {
	c := testClient(t, `{"network":[
		{"node_a_addr":"fd5a:5052:90de::1","node_b_addr":"fd5a:5052:90de::2","ctype":"DOWN","node_b_substrate":"129.22.31.2:5000","link_id":"l1","link_cost":3},
		{"node_a_addr":"fd5a:5052:90de::1","node_b_addr":"fd5a:5052:90de::3","ctype":"UP","node_b_substrate":"10.8.22.1:5000","link_id":"l2","link_cost":1},
		{"node_a_addr":"fd5a:5052:90de::4","node_b_addr":"fd5a:5052:90de::5","ctype":"INVALID","node_b_substrate":"","link_id":"","link_cost":0}
	]}`)

	got, err := c.GetNetwork(context.Background())
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}

	want := []NodeConnection{
		{"fd5a:5052:90de::1", "fd5a:5052:90de::2", "DOWN", "129.22.31.2:5000"},
		{"fd5a:5052:90de::1", "fd5a:5052:90de::3", "UP", "10.8.22.1:5000"},
		{"fd5a:5052:90de::4", "fd5a:5052:90de::5", "INVALID", ""},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d links, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("link %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestGetNetworkSortsNumerically checks ::2 sorts before ::10, which string
// order would get backwards.
func TestGetNetworkSortsNumerically(t *testing.T) {
	c := testClient(t, `{"network":[
		{"node_a_addr":"fd5a:5052:90de::10","node_b_addr":"fd5a:5052:90de::1"},
		{"node_a_addr":"fd5a:5052:90de::2","node_b_addr":"fd5a:5052:90de::10"},
		{"node_a_addr":"fd5a:5052:90de::2","node_b_addr":"fd5a:5052:90de::3"}
	]}`)

	got, err := c.GetNetwork(context.Background())
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}

	want := [][2]string{
		{"fd5a:5052:90de::2", "fd5a:5052:90de::3"},
		{"fd5a:5052:90de::2", "fd5a:5052:90de::10"},
		{"fd5a:5052:90de::10", "fd5a:5052:90de::1"},
	}
	for i, w := range want {
		if got[i].NodeA != w[0] || got[i].NodeB != w[1] {
			t.Errorf("row %d: got %s->%s, want %s->%s", i, got[i].NodeA, got[i].NodeB, w[0], w[1])
		}
	}
}

// TestCompareAddrFallsBackToLexical checks unparseable addresses still get a
// deterministic order.
func TestCompareAddrFallsBackToLexical(t *testing.T) {
	if compareAddr("zzz", "aaa") <= 0 {
		t.Error("expected lexical order for unparseable addresses")
	}
	if compareAddr("fd5a:5052:90de::2", "not-an-addr") >= 0 {
		t.Error("expected lexical fallback when one side fails to parse")
	}
	if compareAddr("fd5a:5052:90de::2", "fd5a:5052:90de::10") >= 0 {
		t.Error("expected ::2 before ::10")
	}
}
