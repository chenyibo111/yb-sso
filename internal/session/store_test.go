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
