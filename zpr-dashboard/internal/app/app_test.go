package app

import (
	"errors"
	"testing"
	"time"

	"neboagency.com/zpr-dashborad/internal/dataplane"
)

// applySnapshot feeds an actorSnapshotMsg through Update and returns the model.
func applySnapshot(t *testing.T, m Model, msg actorSnapshotMsg) Model {
	t.Helper()

	next, _ := m.Update(msg)
	updated, ok := next.(Model)
	if !ok {
		t.Fatalf("Update returned %T, want Model", next)
	}

	return updated
}

// TestSnapshotCommitsResultsIndependently checks a failure on one of the two
// admin calls does not discard the other's fresh result.
func TestSnapshotCommitsResultsIndependently(t *testing.T) {
	actors := []dataplane.ActorDescriptor{{CName: "node-nyc"}}
	network := []dataplane.NodeConnection{{NodeA: "fd5a:5052:90de::1", NodeB: "fd5a:5052:90de::2", CType: "UP"}}
	boom := errors.New("boom")

	// Actors succeed, network fails: actors land, topology stays empty.
	m := applySnapshot(t, InitialModel(), actorSnapshotMsg{actors: actors, networkErr: boom})
	if len(m.state.actor.actors) != 1 {
		t.Error("expected actors to be committed despite the network failure")
	}
	if m.state.actor.network != nil {
		t.Error("expected no topology from a failed network fetch")
	}
	if m.state.actor.networkFetchErr != boom || m.state.actor.fetchErr != nil {
		t.Error("expected only the network error to be recorded")
	}

	// Network succeeds, actors fail: the prior actor list is kept.
	m = applySnapshot(t, m, actorSnapshotMsg{network: network, actorErr: boom})
	if len(m.state.actor.actors) != 1 {
		t.Error("expected the prior actor list to be retained")
	}
	if len(m.state.actor.network) != 1 {
		t.Error("expected topology to be committed despite the actor failure")
	}
	if m.state.actor.fetchErr != boom || m.state.actor.networkFetchErr != nil {
		t.Error("expected only the actor error to be recorded")
	}
}

// TestNetworkErrorAffectsOnlineState checks a failing /admin/network still
// marks the admin service offline.
func TestNetworkErrorAffectsOnlineState(t *testing.T) {
	m := applySnapshot(t, InitialModel(), actorSnapshotMsg{networkErr: errors.New("boom")})

	if m.isAdminOnline() {
		t.Error("expected offline when the network fetch fails")
	}
	if m.adminErr() == nil {
		t.Error("expected the network error to surface as the admin error")
	}
}

// TestSelectionFollowsActorAcrossRefresh checks the selected actor is tracked
// by ZPR address, so an actor joining ahead of it in sort order does not shift
// the selection onto a neighbour — including when the selected actor has no CN.
func TestSelectionFollowsActorAcrossRefresh(t *testing.T) {
	m := applySnapshot(t, InitialModel(), actorSnapshotMsg{
		actors: []dataplane.ActorDescriptor{
			{CName: "node-b", ZprAddress: "fd5a:5052::2"},
			{ZprAddress: "fd5a:5052::3"}, // CN-less
		},
	})
	m.state.actor.selectedIndex = 1

	m = applySnapshot(t, m, actorSnapshotMsg{
		actors: []dataplane.ActorDescriptor{
			{ZprAddress: "fd5a:5052::3"},
			{CName: "node-a", ZprAddress: "fd5a:5052::1"},
			{CName: "node-b", ZprAddress: "fd5a:5052::2"},
		},
	})

	if addr, ok := m.selectedActorAddr(); !ok || addr != "fd5a:5052::3" {
		t.Errorf("selected actor = %q (ok=%v), want fd5a:5052::3", addr, ok)
	}
}

// TestCnLessActorsDoNotAliasInVisaGuard checks the stale-response guard keys
// on the address: with two CN-less actors connected, a visa response for one
// must not be delivered to a selection of the other.
func TestCnLessActorsDoNotAliasInVisaGuard(t *testing.T) {
	m := applySnapshot(t, InitialModel(), actorSnapshotMsg{
		actors: []dataplane.ActorDescriptor{
			{ZprAddress: "fd5a:5052::1"},
			{ZprAddress: "fd5a:5052::2"},
		},
	})
	m.state.actor.selectedIndex = 1 // fd5a:5052::2 after the address sort

	if addr, ok := m.selectedActorAddr(); !ok || addr != "fd5a:5052::2" {
		t.Fatalf("selected actor = %q (ok=%v), want fd5a:5052::2", addr, ok)
	}

	// The other CN-less actor's visas must be dropped, not cross-delivered.
	next, _ := m.Update(actorVisasMsg{addr: "fd5a:5052::1", visas: []dataplane.VisaDescriptor{{ID: 7}}})
	m = next.(Model)
	if m.state.actor.visas != nil {
		t.Error("a CN-less actor accepted another CN-less actor's visa response")
	}

	// The selected actor's own visas land.
	next, _ = m.Update(actorVisasMsg{addr: "fd5a:5052::2", visas: []dataplane.VisaDescriptor{{ID: 9}}})
	m = next.(Model)
	if len(m.state.actor.visas) != 1 || m.state.actor.visas[0].ID != 9 {
		t.Errorf("visas = %+v, want the selected actor's visa 9", m.state.actor.visas)
	}
}

// TestDepartedActorClearsSelectionState checks losing the selected actor drops
// its cached visas and closes the revoke dialogue instead of retargeting it.
func TestDepartedActorClearsSelectionState(t *testing.T) {
	m := applySnapshot(t, InitialModel(), actorSnapshotMsg{
		actors: []dataplane.ActorDescriptor{
			{CName: "node-b", ZprAddress: "fd5a:5052::2"},
			{CName: "node-c", ZprAddress: "fd5a:5052::3"},
		},
	})
	m.state.actor.selectedIndex = 1
	m.state.actor.visas = []dataplane.VisaDescriptor{{ID: 1}}
	m.state.actor.visaCountHistory = []int{1}
	m.state.actor.visasFetchErr = errors.New("stale")
	m.state.actor.revokeOpen = true
	m.state.actor.revokeVisas = true

	m = applySnapshot(t, m, actorSnapshotMsg{
		actors: []dataplane.ActorDescriptor{
			{CName: "node-a", ZprAddress: "fd5a:5052::1"},
			{CName: "node-b", ZprAddress: "fd5a:5052::2"},
		},
	})

	if m.state.actor.visas != nil || m.state.actor.visaCountHistory != nil || m.state.actor.visasFetchErr != nil {
		t.Error("expected the departed actor's visa state to be cleared")
	}
	if m.state.actor.revokeOpen || m.state.actor.revokeVisas {
		t.Error("expected the revoke dialogue to close when its actor disappears")
	}
	if m.state.actor.selectedIndex >= len(m.state.actor.actors) {
		t.Errorf("selectedIndex = %d, out of range for %d actors", m.state.actor.selectedIndex, len(m.state.actor.actors))
	}
}

// TestFormatHeaderClock checks the header clock renders wall-clock time in the
// given moment's zone, with the zone abbreviation appended.
func TestFormatHeaderClock(t *testing.T) {
	zone := time.FixedZone("IST", 5*60*60+30*60)
	now := time.Date(2026, 8, 1, 22, 47, 10, 0, zone)

	if got, want := formatHeaderClock(now), "22:47:10 IST"; got != want {
		t.Errorf("formatHeaderClock = %q, want %q", got, want)
	}
}
