package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"neboagency.com/zpr-dashborad/internal/config"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

func main() {
	command, args := "help", []string(nil)
	if len(os.Args) > 1 {
		command, args = os.Args[1], os.Args[2:]
	}

	if err := dispatch(command, args); err != nil {
		fmt.Fprintf(os.Stderr, "\n==> %v\n", err)
		os.Exit(1)
	}
}

func dispatch(command string, args []string) error {
	if err := rootDir(); err != nil {
		return err
	}

	// The database is the service's, but reaching it does not need it running. (ValKey)
	switch command {
	case "seed":
		return seed()
	case "unseed":
		return unseed()
	}

	ctx := context.Background()

	c, err := client()
	if err != nil {
		return err
	}
	if err := check(ctx, c); err != nil {
		return err
	}

	switch command {
	case "status":
		return status(ctx, c)
	case "revoke":
		return revoke(ctx, c, visaID(args))
	case "unrevoke":
		return unrevoke(ctx, c, visaID(args))
	case "clear":
		return clearRevocations(ctx, c)
	case "run":
		return loop(ctx, c)
	}

	usage()

	return nil
}

// Relative to repo dir
func rootDir() error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return os.Chdir(dir)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("no go.mod above the working directory: run this from the dashboard")
		}
		dir = parent
	}
}

func client() (*dataplane.Client, error) {
	if err := config.Load(); err != nil {
		return nil, err
	}

	return dataplane.NewDefault()
}

func check(ctx context.Context, c *dataplane.Client) error {
	if _, err := c.ListActors(ctx); err != nil {
		return fmt.Errorf(`no visa service at %s — seed it, then start it:
    make seed
    vs <policy.bin2> --config config.toml`, os.Getenv(config.EnvBaseURL))
	}

	return nil
}

func visaID(args []string) int {
	if len(args) > 0 {
		if id, err := strconv.Atoi(args[0]); err == nil {
			return id
		}
	}

	return 1
}

// The loop's period, in seconds, as it was in the shell.
func interval() time.Duration {
	if secs, err := strconv.Atoi(os.Getenv("INTERVAL")); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}

	return 10 * time.Second
}

func say(format string, args ...any) {
	fmt.Printf("\n==> "+format+"\n", args...)
}

func usage() {
	fmt.Printf(`usage: zpr-sim <command>

  seed       write the network into the registry, before the service starts (a fake)
  unseed     remove them again
  status     counts the dashboard is reading right now
  revoke     call the revocation endpoints (placeholders on this build)
  unrevoke   drop the revocation on a visa id (default 1)
  clear      empty the revocation table
  run        loop the revocation calls and status every %ds, until ctrl-c

environment: ZPR_BASE_URL ZPR_KEY_FILE ZPR_DB_ADDR INTERVAL
`, int(interval().Seconds()))
}
