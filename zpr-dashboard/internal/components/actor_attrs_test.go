package components

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

// attrTestNow is the fixed clock the TTL tests measure against.
var attrTestNow = time.Unix(1_700_000_000, 0)

// attrTestActors is a dock, an actor docked to it, an actor docked to an
// address no actor holds, and an actor with no connect_via at all.
var attrTestActors = []dataplane.ActorDescriptor{
	{CName: "node-nyc", ZprAddress: "fd5a:5052:90de::1", Node: true},
	{
		CName:      "adapter-a",
		ZprAddress: "fd5a:5052:90de::10",
		Attrs: []dataplane.Attribute{
			{Key: "zpr.connect_via", Values: []string{"fd5a:5052:90de::1"}},
		},
	},
	{
		CName:      "adapter-b",
		ZprAddress: "fd5a:5052:90de::11",
		Attrs: []dataplane.Attribute{
			{Key: "zpr.connect_via", Values: []string{"fd5a:5052:90de::99"}},
		},
	},
	{CName: "adapter-c", ZprAddress: "fd5a:5052:90de::12"},
	{
		CName:      "adapter-d",
		ZprAddress: "fd5a:5052:90de::13",
		Attrs:      []dataplane.Attribute{{Key: "zpr.connect_via"}},
	},
}

// TestActorDock checks CN resolution, the raw-address fallback, and that a
// missing or empty attribute value yields "" without panicking.
func TestActorDock(t *testing.T) {
	cases := []struct {
		actor int
		want  string
	}{
		{1, "node-nyc"},
		{2, "fd5a:5052:90de::99"},
		{3, ""},
		{4, ""},
	}

	for _, c := range cases {
		actor := attrTestActors[c.actor]
		if got := actorDock(attrTestActors, actor); got != c.want {
			t.Errorf("actorDock(%s) = %q, want %q", actor.CName, got, c.want)
		}
	}
}

// TestFormatTTL checks the native duration rendering plus the no-expiry and
// already-expired cases.
func TestFormatTTL(t *testing.T) {
	cases := []struct {
		offset time.Duration
		want   string
	}{
		{4*time.Hour + 23*time.Minute + 7*time.Second, "4h23m7s"},
		{42 * time.Minute, "42m0s"},
		{26*time.Hour + 3*time.Minute, "26h3m0s"},
		{-time.Second, "expired"},
		{0, "expired"},
		{100 * 365 * 24 * time.Hour, "100y"},
	}

	for _, c := range cases {
		expires := attrTestNow.Add(c.offset).Unix()
		if got := formatTTL(expires, attrTestNow); got != c.want {
			t.Errorf("formatTTL(+%s) = %q, want %q", c.offset, got, c.want)
		}
	}

	if got := formatTTL(0, attrTestNow); got != "" {
		t.Errorf("formatTTL(0) = %q, want empty", got)
	}
}

// TestDisplayAttrs checks zpr.-prefixed keys are filtered and the incoming
// order is preserved — GetActor already sorts by key.
func TestDisplayAttrs(t *testing.T) {
	actor := dataplane.ActorDescriptor{Attrs: []dataplane.Attribute{
		{Key: "org.team"},
		{Key: "user.hair_color"},
		{Key: "zpr.connect_via"},
		{Key: "zpr.role"},
	}}

	got := displayAttrs(actor)

	want := []string{"org.team", "user.hair_color"}
	if len(got) != len(want) {
		t.Fatalf("displayAttrs returned %d attrs, want %d", len(got), len(want))
	}
	for i, key := range want {
		if got[i].Key != key {
			t.Errorf("attr %d = %q, want %q", i, got[i].Key, key)
		}
	}

	if len(actor.Attrs) != 4 {
		t.Error("displayAttrs must not modify the actor's own attribute slice")
	}
}

// TestFormatAttr checks value joining, the TTL suffix, and its omission for
// attributes that never expire.
func TestFormatAttr(t *testing.T) {
	cases := []struct {
		attr dataplane.Attribute
		want string
	}{
		{dataplane.Attribute{Key: "user.hair_color", Values: []string{"brown"}}, "user.hair_color brown"},
		{
			dataplane.Attribute{
				Key:       "user.hair_color",
				Values:    []string{"brown"},
				ExpiresAt: attrTestNow.Add(4*time.Hour + 23*time.Minute).Unix(),
			},
			"user.hair_color brown (4h23m0s)",
		},
		{dataplane.Attribute{Key: "org.team", Values: []string{"blue", "green"}}, "org.team blue,green"},
		{dataplane.Attribute{Key: "org.team"}, "org.team "},
	}

	for _, c := range cases {
		if got := ansi.Strip(formatAttr(c.attr, attrTestNow)); got != c.want {
			t.Errorf("formatAttr(%s) = %q, want %q", c.attr.Key, got, c.want)
		}
	}
}

// renderDetails renders the Actor Details pane with ANSI stripped.
func renderDetails(t *testing.T, height int, actors []dataplane.ActorDescriptor, selected int, fetchErr error) string {
	t.Helper()
	return ansi.Strip(ActorDetails(80, height, actors, selected, fetchErr))
}

// TestActorDetailsDock checks the Dock line shows the CN when known, the raw
// address when not, and "unknown" when connect_via is missing.
func TestActorDetailsDock(t *testing.T) {
	cases := []struct {
		actor int
		want  string
	}{
		{1, "Dock node-nyc"},
		{2, "Dock fd5a:5052:90de::99"},
		{3, "Dock unknown"},
		{4, "Dock unknown"},
	}

	for _, c := range cases {
		out := renderDetails(t, 30, attrTestActors, c.actor, nil)
		if !strings.Contains(out, c.want) {
			t.Errorf("actor %d: expected %q in output:\n%s", c.actor, c.want, out)
		}
	}
}

// TestActorDetailsSubstrateAddress checks the address renders verbatim and the
// line is dropped when the attribute is missing or carries no value.
func TestActorDetailsSubstrateAddress(t *testing.T) {
	actors := []dataplane.ActorDescriptor{
		{CName: "with", Attrs: []dataplane.Attribute{
			{Key: "zpr.substrate_addr", Values: []string{"[fd5a:5052::100]:1234"}},
		}},
		{CName: "empty-value", Attrs: []dataplane.Attribute{{Key: "zpr.substrate_addr"}}},
		{CName: "missing"},
	}

	if out := renderDetails(t, 30, actors, 0, nil); !strings.Contains(out, "Substrate Address [fd5a:5052::100]:1234") {
		t.Errorf("expected the substrate address verbatim:\n%s", out)
	}

	for _, i := range []int{1, 2} {
		if out := renderDetails(t, 30, actors, i, nil); strings.Contains(out, "Substrate Address") {
			t.Errorf("actor %d: expected no substrate line:\n%s", i, out)
		}
	}
}

// TestActorDetailsConnectedAdapters checks the count for a node, "unknown"
// when its details are missing, and no line at all for an adapter.
func TestActorDetailsConnectedAdapters(t *testing.T) {
	actors := []dataplane.ActorDescriptor{
		{CName: "node-with", Node: true, NodeDetails: &dataplane.NodeRecordBrief{
			Adapters: []string{"adapter-a", "adapter-b"},
		}},
		{CName: "node-bare", Node: true},
		{CName: "adapter-a"},
	}

	if out := renderDetails(t, 30, actors, 0, nil); !strings.Contains(out, "Connected Adapters 2") {
		t.Errorf("expected the adapter count:\n%s", out)
	}

	if out := renderDetails(t, 30, actors, 1, nil); !strings.Contains(out, "Connected Adapters unknown") {
		t.Errorf("expected unknown adapters for a node without details:\n%s", out)
	}

	if out := renderDetails(t, 30, actors, 2, nil); strings.Contains(out, "Connected Adapters") {
		t.Errorf("expected no adapter line for an adapter:\n%s", out)
	}
}

// TestActorDetailsCustomAttributes checks non-zpr attributes render with their
// TTL and zpr. ones stay hidden.
func TestActorDetailsCustomAttributes(t *testing.T) {
	actors := []dataplane.ActorDescriptor{{CName: "adapter-a", Attrs: []dataplane.Attribute{
		{Key: "zpr.role", Values: []string{"adapter"}},
		{Key: "user.hair_color", Values: []string{"brown"}},
	}}}

	out := renderDetails(t, 30, actors, 0, nil)

	if !strings.Contains(out, "user.hair_color brown") {
		t.Errorf("expected the custom attribute:\n%s", out)
	}
	if strings.Contains(out, "zpr.role") {
		t.Errorf("expected zpr. attributes to stay hidden:\n%s", out)
	}
}

// TestActorDetailsOverflowKeepsFooterAndWarning checks a short pane still
// shows the "+N more attributes" footer and the refresh warning.
func TestActorDetailsOverflowKeepsFooterAndWarning(t *testing.T) {
	var attrs []dataplane.Attribute
	for _, key := range []string{"a.one", "b.two", "c.three", "d.four", "e.five", "f.six"} {
		attrs = append(attrs, dataplane.Attribute{Key: key, Values: []string{"v"}})
	}

	actors := []dataplane.ActorDescriptor{{CName: "adapter-a", Attrs: attrs}}

	out := renderDetails(t, 13, actors, 0, errors.New("stale"))

	if !strings.Contains(out, "more attribute") {
		t.Errorf("expected the overflow footer:\n%s", out)
	}
	if !strings.Contains(out, "last refresh failed") {
		t.Errorf("expected the refresh warning:\n%s", out)
	}
	// Core fields outrank attributes for the space available.
	if !strings.Contains(out, "Name adapter-a") {
		t.Errorf("expected core fields to survive:\n%s", out)
	}
}

// TestActorServicesOfferedEndpoints checks the Endpoints column renders, other
// actors' services are excluded, and filtering keeps FetchServices' name order.
func TestActorServicesOfferedEndpoints(t *testing.T) {
	actors := []dataplane.ActorDescriptor{{CName: "adapter-a"}}
	services := []dataplane.ServiceDescriptor{
		{ServiceName: "alpha", ActorCN: "adapter-a", Endpoints: "TCP/80"},
		{ServiceName: "other", ActorCN: "adapter-b", Endpoints: "TCP/22"},
		{ServiceName: "zebra", ActorCN: "adapter-a", Endpoints: "UDP/53"},
	}

	out := ansi.Strip(ActorServicesOffered(80, 20, actors, 0, services, nil, nil, nil))

	if !strings.Contains(out, "TCP/80") || !strings.Contains(out, "UDP/53") {
		t.Errorf("expected endpoints in the table:\n%s", out)
	}
	if strings.Contains(out, "other") {
		t.Errorf("expected another actor's service to be excluded:\n%s", out)
	}
	if strings.Index(out, "alpha") > strings.Index(out, "zebra") {
		t.Errorf("expected the incoming service order to be preserved:\n%s", out)
	}
	// A successful refresh that found no visas is a real count of zero.
	if got := rowCell(t, out, "alpha"); got != "0" {
		t.Errorf("alpha count = %q, want 0 for an empty visa set:\n%s", got, out)
	}
}

// offeredFixture returns the actor, services and visas the Visas-column tests
// share: alpha and beta answer on the same actor address and are told apart by
// port alone, alpha also answers on a dock address, and quiet gets nothing.
func offeredFixture() ([]dataplane.ActorDescriptor, []dataplane.ServiceDescriptor, []dataplane.VisaDescriptor) {
	actors := []dataplane.ActorDescriptor{{CName: "alpha-cn"}}
	services := []dataplane.ServiceDescriptor{
		{ServiceName: "alpha", ActorCN: "alpha-cn", ZprAddress: "fd5a:5052:90de::30", DockZprAddress: "fd5a:5052:90de::99", Endpoints: "TCP/443"},
		{ServiceName: "beta", ActorCN: "alpha-cn", ZprAddress: "fd5a:5052:90de::30", Endpoints: "TCP/9000"},
		{ServiceName: "quiet", ActorCN: "alpha-cn", ZprAddress: "fd5a:5052:90de::31", Endpoints: "TCP/8080"},
	}
	visas := []dataplane.VisaDescriptor{
		// Forward and reverse halves of one flow towards alpha.
		{ID: 1, Direction: "forward", Proto: "TCP", SourceAddr: strPtr("fd5a:5052:90de::40"), DestAddr: strPtr("fd5a:5052:90de::30"), SourcePort: intPtr(0), DestPort: intPtr(443)},
		{ID: 2, Direction: "reverse", Proto: "TCP", SourceAddr: strPtr("fd5a:5052:90de::30"), DestAddr: strPtr("fd5a:5052:90de::40"), SourcePort: intPtr(443), DestPort: intPtr(0)},
		// Towards alpha on its dock address.
		{ID: 3, Direction: "forward", Proto: "TCP", SourceAddr: strPtr("fd5a:5052:90de::40"), DestAddr: strPtr("fd5a:5052:90de::99"), SourcePort: intPtr(0), DestPort: intPtr(443)},
		// Nobody's service.
		{ID: 4, Direction: "forward", Proto: "TCP", SourceAddr: strPtr("fd5a:5052:90de::31"), DestAddr: strPtr("fd5a:5052:90de::40"), SourcePort: intPtr(0), DestPort: intPtr(22)},
		// Same address as alpha, beta's port.
		{ID: 5, Direction: "forward", Proto: "TCP", SourceAddr: strPtr("fd5a:5052:90de::40"), DestAddr: strPtr("fd5a:5052:90de::30"), SourcePort: intPtr(0), DestPort: intPtr(9000)},
	}

	return actors, services, visas
}

// rowCell returns the trailing count cell of the rendered row naming svc.
func rowCell(t *testing.T, out, svc string) string {
	t.Helper()

	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, svc) {
			continue
		}
		fields := strings.Fields(strings.Trim(line, " │"))
		return fields[len(fields)-1]
	}

	t.Fatalf("no row for %q:\n%s", svc, out)
	return ""
}

// TestActorServicesOfferedVisaCounts checks the Visas column counts the visas
// granted for each service's endpoints — both directions, and per port rather
// than per address, so two services on one address differ.
func TestActorServicesOfferedVisaCounts(t *testing.T) {
	actors, services, visas := offeredFixture()

	out := ansi.Strip(ActorServicesOffered(80, 20, actors, 0, services, visas, nil, nil))

	// Forward, its reverse half, and the dock-address visa.
	if got := rowCell(t, out, "alpha"); got != "3" {
		t.Errorf("alpha count = %q, want 3:\n%s", got, out)
	}
	// Same address as alpha, so an address-only match would report 3 here too.
	if got := rowCell(t, out, "beta"); got != "1" {
		t.Errorf("beta count = %q, want 1:\n%s", got, out)
	}
	// ::31 only ever appears as a forward source, and ::40 is nobody's service.
	if got := rowCell(t, out, "quiet"); got != "0" {
		t.Errorf("quiet count = %q, want 0:\n%s", got, out)
	}
}

// TestActorServicesOfferedVisaError checks a failed visa refresh renders ERR
// instead of counting the retained (now stale) visa slice.
func TestActorServicesOfferedVisaError(t *testing.T) {
	actors, services, visas := offeredFixture()

	out := ansi.Strip(ActorServicesOffered(80, 20, actors, 0, services, visas, nil, errors.New("stale")))

	for _, svc := range []string{"alpha", "beta", "quiet"} {
		if got := rowCell(t, out, svc); got != "ERR" {
			t.Errorf("%s count = %q, want ERR:\n%s", svc, got, out)
		}
	}
	// Service names stay useful even when the counts cannot be trusted.
	if !strings.Contains(out, "alpha") {
		t.Errorf("expected the pane to still list services:\n%s", out)
	}
}

// strPtr returns a pointer to s, for the optional visa address fields.
func strPtr(s string) *string { return &s }

// intPtr returns a pointer to n, for the optional visa port fields.
func intPtr(n int) *int { return &n }
