package session

import (
	"testing"
	"time"
)

func TestSessionDeadlineRequiresBothAbsoluteAndRecentActivity(t *testing.T) {
	start := time.Date(2026, 11, 14, 1, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		last time.Time
		now  time.Time
		want bool
	}{
		{"active", start.Add(7*time.Hour + 45*time.Minute), start.Add(7*time.Hour + 59*time.Minute), true},
		{"idle boundary", start, start.Add(30 * time.Minute), false},
		{"absolute boundary", start.Add(7*time.Hour + 59*time.Minute), start.Add(8 * time.Hour), false},
		{"expired activity cannot revive", start, start.Add(31 * time.Minute), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sessionWithinDeadline(start, tc.last, tc.now); got != tc.want {
				t.Fatalf("sessionWithinDeadline() = %v, want %v", got, tc.want)
			}
		})
	}
}
