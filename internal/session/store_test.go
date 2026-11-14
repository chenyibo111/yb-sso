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

func TestPostgresSessionDeadlineCannotBeRevived(t *testing.T) {
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
	sid := fmt.Sprintf("deadline-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), "DELETE FROM sso_browser_sessions WHERE sid=$1", sid)
	})
	if active, err := store.Active(ctx, sid, false); err != nil || !active {
		t.Fatalf("new sid: %v %v", active, err)
	}
	_, err = store.pool.Exec(ctx, "UPDATE sso_browser_sessions SET last_activity_at=now()-interval '20 minutes' WHERE sid=$1", sid)
	if err != nil {
		t.Fatal(err)
	}
	var before, after time.Time
	if err := store.pool.QueryRow(ctx, "SELECT last_activity_at FROM sso_browser_sessions WHERE sid=$1", sid).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if active, err := store.Active(ctx, sid, false); err != nil || !active {
		t.Fatalf("status check: %v %v", active, err)
	}
	if err := store.pool.QueryRow(ctx, "SELECT last_activity_at FROM sso_browser_sessions WHERE sid=$1", sid).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !before.Equal(after) {
		t.Fatalf("background status refreshed idle time: %s -> %s", before, after)
	}
	_, err = store.pool.Exec(ctx, "UPDATE sso_browser_sessions SET last_activity_at=now()-interval '31 minutes' WHERE sid=$1", sid)
	if err != nil {
		t.Fatal(err)
	}
	if active, err := store.Active(ctx, sid, true); err != nil || active {
		t.Fatalf("idle sid revived: %v %v", active, err)
	}
	if active, err := store.Active(ctx, sid, false); err != nil || active {
		t.Fatalf("idle sid became active: %v %v", active, err)
	}
	absoluteSID := sid + "-absolute"
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), "DELETE FROM sso_browser_sessions WHERE sid=$1", absoluteSID)
	})
	if active, err := store.Active(ctx, absoluteSID, false); err != nil || !active {
		t.Fatalf("new absolute sid: %v %v", active, err)
	}
	_, err = store.pool.Exec(ctx, "UPDATE sso_browser_sessions SET started_at=now()-interval '8 hours' WHERE sid=$1", absoluteSID)
	if err != nil {
		t.Fatal(err)
	}
	if active, err := store.Active(ctx, absoluteSID, true); err != nil || active {
		t.Fatalf("absolute deadline revived: %v %v", active, err)
	}
}

func TestPostgresVerifiedIdentitySurvivesRestartAndRefreshes(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for PostgreSQL integration test")
	}
	ctx := context.Background()
	store, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	subject := fmt.Sprintf("fs_test_%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), "DELETE FROM sso_verified_identities WHERE subject=$1", subject)
		store.Close()
	})
	if err := store.Save(ctx, subject, map[string]string{"feishu_open_id": "ou_test", "name": "first"}); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	claims, err := second.Load(ctx, subject)
	if err != nil || claims["feishu_open_id"] != "ou_test" {
		t.Fatalf("stored identity not restored: %v %v", claims, err)
	}
	if err := second.Save(ctx, subject, map[string]string{"feishu_open_id": "ou_test", "name": "updated"}); err != nil {
		t.Fatal(err)
	}
	claims, err = store.Load(ctx, subject)
	if err != nil || claims["name"] != "updated" {
		t.Fatalf("stored identity not refreshed: %v %v", claims, err)
	}
}
