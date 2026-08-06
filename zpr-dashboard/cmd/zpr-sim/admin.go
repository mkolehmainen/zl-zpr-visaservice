package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"neboagency.com/zpr-dashborad/internal/config"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

func status(ctx context.Context, c *dataplane.Client) error {
	say("what the dashboard is reading from %s", os.Getenv(config.EnvBaseURL))

	actors, err := c.ListActors(ctx)
	count("actors", len(actors), err)

	services, err := c.ListServices(ctx)
	count("services", len(services), err)

	visas, err := c.ListVisas(ctx)
	count("visas", len(visas), err)

	revocations, err := c.ListRevocations(ctx)
	count("authrevoke", len(revocations), err)

	fmt.Printf("    %-12s %s\n", "policy", policyLine(ctx, c))

	return nil
}

func policyLine(ctx context.Context, c *dataplane.Client) string {
	bundle, err := c.GetCurrentPolicy(ctx)
	if err != nil {
		return "unavailable"
	}

	return fmt.Sprintf("config %d · %s · %d bytes", bundle.ConfigID, bundle.Format, bundle.Size())
}

func count(name string, total int, err error) {
	if err != nil {
		fmt.Printf("    %-12s %s\n", name, "unavailable")
		return
	}

	fmt.Printf("    %-12s %d\n", name, total)
}

func revoke(ctx context.Context, c *dataplane.Client, id int) error {
	say("revoking visa %d", id)

	fmt.Printf("    POST   authrevoke/%-3d %s\n", id, reply(c.Post(ctx, revocation(id), nil)))
	fmt.Printf("    GET    authrevoke     %s\n", reply(c.Get(ctx, "/admin/authrevoke")))

	return nil
}

func unrevoke(ctx context.Context, c *dataplane.Client, id int) error {
	say("dropping the revocation on visa %d", id)

	fmt.Printf("    DELETE authrevoke/%-3d %s\n", id, reply(c.Delete(ctx, revocation(id))))
	fmt.Printf("    GET    authrevoke     %s\n", reply(c.Get(ctx, "/admin/authrevoke")))

	return nil
}

func clearRevocations(ctx context.Context, c *dataplane.Client) error {
	say("clearing the revocation table")

	fmt.Printf("    POST   authrevoke/clear %s\n", reply(c.Post(ctx, "/admin/authrevoke/clear", nil)))

	return nil
}

func revocation(id int) string { return fmt.Sprintf("/admin/authrevoke/%d", id) }

func reply(resp *http.Response, err error) string {
	if err != nil {
		return err.Error()
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err.Error()
	}

	return strings.TrimSpace(string(body))
}
