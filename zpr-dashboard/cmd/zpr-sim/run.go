package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"neboagency.com/zpr-dashborad/internal/dataplane"
)

func loop(ctx context.Context, c *dataplane.Client) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	for n := 1; ; n++ {
		fmt.Printf("\n───── round %d ─────\n", n)

		var err error
		if n%5 == 0 {
			err = clearRevocations(ctx, c)
		} else {
			err = revoke(ctx, c, n%5)
		}
		if err == nil {
			err = status(ctx, c)
		}

		// Ctrl-c cancels whatever call the round was making.
		if err != nil && ctx.Err() == nil {
			return err
		}

		select {
		case <-time.After(interval()):
		case <-ctx.Done():
			return nil
		}
	}
}
