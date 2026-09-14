package components

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

// The address-keyed fixtures: a CN-less (OIDC-only) actor and a named one,
// plus a second CN-less actor for the aliasing cases.
var addrKeyActors = []dataplane.ActorDescriptor{
	{ZprAddress: "fd5a:5052::1"}, // CN-less
	{CName: "node-a", ZprAddress: "fd5a:5052::2"},
	{ZprAddress: "fd5a:5052::3"}, // second CN-less
}

// TestActorLabel pins the label rule: the CN when present, the address
// otherwise — the established deny_list fallback, applied everywhere.
func TestActorLabel(t *testing.T) {
	cases := []struct {
		actor dataplane.ActorDescriptor
		want  string
	}{
		{dataplane.ActorDescriptor{CName: "node-a", ZprAddress: "fd5a:5052::2"}, "node-a"},
		{dataplane.ActorDescriptor{ZprAddress: "fd5a:5052::1"}, "fd5a:5052::1"},
		{dataplane.ActorDescriptor{}, ""},
	}

	for _, c := range cases {
		if got := actorLabel(c.actor); got != c.want {
			t.Errorf("actorLabel(%+v) = %q, want %q", c.actor, got, c.want)
		}
	}
}

// TestActorListLabelsCnLessActorWithAddress checks a CN-less actor's row is
// labelled with its address rather than rendering blank.
func TestActorListLabelsCnLessActorWithAddress(t *testing.T) {
	out := ansi.Strip(ActorList(120, 20, addrKeyActors, -1, false, nil))

	if !strings.Contains(out, "fd5a:5052::1") {
		t.Errorf("expected the CN-less actor's address in the list:\n%s", out)
	}
	if !strings.Contains(out, "node-a") {
		t.Errorf("expected the named actor's CN in the list:\n%s", out)
	}
}

// TestServiceCertificateJoinsOwnerByAddress checks the service → owning actor
// join keys on the service's zpr_addr, so a CN-less owner is still found.
func TestServiceCertificateJoinsOwnerByAddress(t *testing.T) {
	exp := int64(4102444800) // far future
	actors := []dataplane.ActorDescriptor{
		{ZprAddress: "fd5a:5052::1", AuthExp: &exp}, // CN-less owner
	}
	services := []dataplane.ServiceDescriptor{
		{ServiceName: "alpha", ZprAddress: "fd5a:5052::1"},
	}

	out := ansi.Strip(ServiceCertificate(80, 20, services, 0, actors, nil))

	if strings.Contains(out, "Owning actor not connected") {
		t.Errorf("expected the CN-less owner to be found by address:\n%s", out)
	}
	if !strings.Contains(out, "Expires") {
		t.Errorf("expected the certificate pane to render the owner's expiry:\n%s", out)
	}
}

// TestActorServicesOfferedJoinsByAddress checks the actor → services join
// keys on the address, so a CN-less actor still lists its services.
func TestActorServicesOfferedJoinsByAddress(t *testing.T) {
	actors := []dataplane.ActorDescriptor{{ZprAddress: "fd5a:5052::1"}}
	services := []dataplane.ServiceDescriptor{
		{ServiceName: "alpha", ZprAddress: "fd5a:5052::1", Endpoints: "TCP/80"},
		{ServiceName: "other", ZprAddress: "fd5a:5052::9", Endpoints: "TCP/22"},
	}

	out := ansi.Strip(ActorServicesOffered(80, 20, actors, 0, services, nil, nil, nil))

	if !strings.Contains(out, "alpha") {
		t.Errorf("expected the CN-less actor's service:\n%s", out)
	}
	if strings.Contains(out, "other") {
		t.Errorf("expected another actor's service to be excluded:\n%s", out)
	}
}

// TestAbsentServicesJoinsByAddress checks the absent-services alert keys on
// the address: a CN-less actor's service is present, an unclaimed address is
// absent.
func TestAbsentServicesJoinsByAddress(t *testing.T) {
	services := []dataplane.ServiceDescriptor{
		{ServiceName: "covered", ZprAddress: "fd5a:5052::1"},
		{ServiceName: "orphan", ZprAddress: "fd5a:5052::99"},
	}

	absent := absentServices(services, addrKeyActors)

	if len(absent) != 1 || absent[0] != "orphan" {
		t.Errorf("absentServices = %v, want [orphan]", absent)
	}
}

// TestDistinctActorsCountsByAddress checks the service list's distinct-actor
// count keys on the address, so two CN-less actors count as two.
func TestDistinctActorsCountsByAddress(t *testing.T) {
	services := []dataplane.ServiceDescriptor{
		{ServiceName: "a", ZprAddress: "fd5a:5052::1"},
		{ServiceName: "b", ZprAddress: "fd5a:5052::3"},
		{ServiceName: "c", ZprAddress: "fd5a:5052::3"},
	}

	if got := distinctActors(services); got != 2 {
		t.Errorf("distinctActors = %d, want 2 — CN-less actors must not collapse", got)
	}
}

// TestServiceListLabelsCnLessActorWithAddress checks the Actor column falls
// back to the service's address when its actor has no CN.
func TestServiceListLabelsCnLessActorWithAddress(t *testing.T) {
	services := []dataplane.ServiceDescriptor{
		{ServiceName: "alpha", ActorCN: "", ZprAddress: "fd5a:5052::1"},
	}

	out := ansi.Strip(ServiceList(120, 20, services, -1, nil))

	if !strings.Contains(out, "fd5a:5052::1") {
		t.Errorf("expected the address label for a CN-less actor's service:\n%s", out)
	}
}

// TestVisaSubjectLabelsCnLessActorWithAddress checks the visa table's subject
// column labels a CN-less requesting node with its address.
func TestVisaSubjectLabelsCnLessActorWithAddress(t *testing.T) {
	visa := dataplane.VisaDescriptor{RequestingNode: "fd5a:5052::1"}

	if got := visaSubject(visa, addrKeyActors); got != "fd5a:5052::1" {
		t.Errorf("visaSubject = %q, want the CN-less actor's address", got)
	}

	visa.RequestingNode = "fd5a:5052::2"
	if got := visaSubject(visa, addrKeyActors); got != "node-a" {
		t.Errorf("visaSubject = %q, want node-a", got)
	}
}

// TestExpiredActorsLabelsCnLessActorWithAddress checks the expired-auth alert
// names a CN-less actor by its address.
func TestExpiredActorsLabelsCnLessActorWithAddress(t *testing.T) {
	exp := int64(1) // long past
	actors := []dataplane.ActorDescriptor{
		{ZprAddress: "fd5a:5052::1", AuthExp: &exp},
	}

	expired := expiredActors(actors)

	if len(expired) != 1 || expired[0] != "fd5a:5052::1" {
		t.Errorf("expiredActors = %v, want the actor's address", expired)
	}
}
