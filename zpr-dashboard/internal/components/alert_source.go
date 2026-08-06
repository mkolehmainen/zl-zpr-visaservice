package components

import (
	"fmt"
	"sort"
	"strings"

	"neboagency.com/zpr-dashborad/internal/dataplane"
)

type AlertType int

const (
	AlertTypeWarning AlertType = iota
	AlertTypeAlert
)

type Alert struct {
	Key    string
	Type   AlertType
	Title  string
	Detail string
	Risk   RiskLevel
}

type AlertInputs struct {
	Online        bool
	AdminErr      error
	Actors        []dataplane.ActorDescriptor
	Services      []dataplane.ServiceDescriptor
	Visas         []dataplane.VisaDescriptor
	Revocations   []dataplane.AuthRevokeDescriptor
	AppliedPolicy *dataplane.PolicyBundle
}

func DeriveAlerts(in AlertInputs) []Alert {
	var alerts []Alert

	if !in.Online {
		detail := "the admin API is not answering"
		if in.AdminErr != nil {
			detail = in.AdminErr.Error()
		}

		alerts = append(alerts, Alert{
			Key:    "admin-offline",
			Type:   AlertTypeAlert,
			Title:  "Visa service unreachable",
			Detail: detail,
			Risk:   RiskHigh,
		})

		return alerts
	}

	if in.AppliedPolicy == nil {
		alerts = append(alerts, Alert{
			Key:    "no-policy",
			Type:   AlertTypeAlert,
			Title:  "No policy applied",
			Detail: "the service reports no current policy bundle",
			Risk:   RiskHigh,
		})
	}

	if expired := expiredActors(in.Actors); len(expired) > 0 {
		alerts = append(alerts, Alert{
			Key:    "auth-expired",
			Type:   AlertTypeAlert,
			Title:  fmt.Sprintf("%d actor %s expired", len(expired), plural(len(expired), "authorization")),
			Detail: strings.Join(expired, ", "),
			Risk:   RiskHigh,
		})
	}

	if n := len(in.Revocations); n > 0 {
		alerts = append(alerts, Alert{
			Key:    "revocations",
			Type:   AlertTypeAlert,
			Title:  fmt.Sprintf("%d authorization %s recorded", n, plural(n, "revocation")),
			Detail: revocationDetail(in.Revocations),
			Risk:   RiskMedium,
		})
	}

	if n := ExpiringVisas(in.Visas); n > 0 {
		alerts = append(alerts, Alert{
			Key:    "visas-expiring",
			Type:   AlertTypeWarning,
			Title:  fmt.Sprintf("%d %s expiring within the hour", n, plural(n, "visa")),
			Detail: "the nodes holding them will need to re-request",
			Risk:   RiskMedium,
		})
	}

	if absent := absentServices(in.Services, in.Actors); len(absent) > 0 {
		alerts = append(alerts, Alert{
			Key:    "services-absent",
			Type:   AlertTypeWarning,
			Title:  fmt.Sprintf("%d %s with no connected actor", len(absent), plural(len(absent), "service")),
			Detail: strings.Join(absent, ", "),
			Risk:   RiskMedium,
		})
	}

	if n := undescribedActors(in.Actors); n > 0 {
		alerts = append(alerts, Alert{
			Key:    "actors-undescribed",
			Type:   AlertTypeWarning,
			Title:  fmt.Sprintf("%d %s cannot be described", n, plural(n, "actor")),
			Detail: "the roster names them but their detail lookup fails",
			Risk:   RiskLow,
		})
	}

	// Stable within a risk level, so the panel doesn't shuffle every refresh
	sort.SliceStable(alerts, func(i, j int) bool { return alerts[i].Risk > alerts[j].Risk })

	return alerts
}

func expiredActors(actors []dataplane.ActorDescriptor) []string {
	var expired []string
	for _, actor := range actors {
		if ActorAuthState(actor) == AuthExpired {
			expired = append(expired, actor.CName)
		}
	}

	return expired
}

func undescribedActors(actors []dataplane.ActorDescriptor) int {
	count := 0
	for _, actor := range actors {
		if actor.ZprAddress == "" {
			count++
		}
	}

	return count
}

func absentServices(services []dataplane.ServiceDescriptor, actors []dataplane.ActorDescriptor) []string {
	var absent []string
	for _, service := range services {
		if _, ok := actorByCN(actors, service.ActorCN); !ok {
			absent = append(absent, service.ServiceName)
		}
	}

	return absent
}

func revocationDetail(revocations []dataplane.AuthRevokeDescriptor) string {
	ids := make([]string, 0, 3)
	for i, revocation := range revocations {
		if i == 3 {
			break
		}

		ids = append(ids, fmt.Sprintf("%d", revocation.ID))
	}

	detail := "visa " + strings.Join(ids, ", ")
	if len(revocations) > 3 {
		detail += fmt.Sprintf(", +%d more", len(revocations)-3)
	}

	return detail
}

func KeepUndismissed(alerts []Alert, dismissed map[string]bool) []Alert {
	if len(dismissed) == 0 {
		return alerts
	}

	kept := make([]Alert, 0, len(alerts))
	for _, alert := range alerts {
		if !dismissed[alert.Key] {
			kept = append(kept, alert)
		}
	}

	return kept
}

func AlertKeys(alerts []Alert) []string {
	keys := make([]string, 0, len(alerts))
	for _, alert := range alerts {
		keys = append(keys, alert.Key)
	}

	return keys
}
