package session

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestPostgresRevocationIsSpecificAndPersistent(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for PostgreSQL integration test")
	}
	ctx := context.Background()
	store, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sid := fmt.Sprintf("test-%d", time.Now().UnixNano())
	other := sid + "-other"
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), "DELETE FROM sso_revoked_sessions WHERE sid=$1", sid)
	})
	if revoked, err := store.Revoked(ctx, sid); err != nil || revoked {
		t.Fatalf("new session should be active: %v, %v", revoked, err)
	}
	if err := store.Revoke(ctx, sid); err != nil {
		t.Fatal(err)
	}
	if revoked, err := store.Revoked(ctx, sid); err != nil || !revoked {
		t.Fatalf("revoked session should be rejected: %v, %v", revoked, err)
	}
	if revoked, err := store.Revoked(ctx, other); err != nil || revoked {
		t.Fatalf("other session should stay active: %v, %v", revoked, err)
	}
	second, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if revoked, err := second.Revoked(ctx, sid); err != nil || !revoked {
		t.Fatalf("revocation did not persist: %v, %v", revoked, err)
	}
}
