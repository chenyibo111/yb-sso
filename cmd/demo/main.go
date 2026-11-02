package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/chenyibo111/yb-sso/internal/demo"
)

func main() {
	port := flag.Int("port", 3100, "demo app port: 3100 or 3101")
	flag.Parse()
	h, err := newDemoWithRetry(context.Background(), *port, 12, time.Second, demo.New)
	if err != nil {
		log.Fatal(err)
	}
	bind := os.Getenv("DEMO_BIND_ADDRESS")
	if bind == "" {
		bind = "127.0.0.1"
	}
	srv := &http.Server{Addr: bind + ":" + strconv.Itoa(*port), Handler: h, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("demo app listening on http://localhost:%d", *port)
	log.Fatal(srv.ListenAndServe())
}

func newDemoWithRetry(ctx context.Context, port, attempts int, delay time.Duration, create func(context.Context, int) (http.Handler, error)) (http.Handler, error) {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		h, err := create(ctx, port)
		if err == nil {
			return h, nil
		}
		lastErr = err
		if attempt == attempts {
			break
		}
		log.Printf("demo startup attempt %d/%d failed: %v", attempt, attempts, err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil, fmt.Errorf("demo startup failed after %d attempts: %w", attempts, lastErr)
}
