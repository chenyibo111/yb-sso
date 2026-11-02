package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestDemoStartupWaitsForHydra(t *testing.T) {
	attempts := 0
	want := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	got, err := newDemoWithRetry(context.Background(), 3100, 3, time.Millisecond, func(context.Context, int) (http.Handler, error) {
		attempts++
		if attempts < 3 {
			return nil, errors.New("Hydra unavailable")
		}
		return want, nil
	})
	if err != nil || got == nil || attempts != 3 {
		t.Fatalf("got handler=%v error=%v attempts=%d; want handler and 3 attempts", got != nil, err, attempts)
	}
}

func TestDemoStartupStopsAfterRetryLimit(t *testing.T) {
	attempts := 0
	_, err := newDemoWithRetry(context.Background(), 3100, 2, time.Millisecond, func(context.Context, int) (http.Handler, error) {
		attempts++
		return nil, errors.New("Hydra unavailable")
	})
	if err == nil || attempts != 2 {
		t.Fatalf("got error=%v attempts=%d; want error after 2 attempts", err, attempts)
	}
}
