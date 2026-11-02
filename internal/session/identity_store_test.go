package session

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/chenyibo111/yb-sso/internal/feishu"
)

func TestMemberIdentityPersistsAcrossStoreInstances(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for PostgreSQL integration test")
	}
	ctx := context.Background()
	first, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	subject := fmt.Sprintf("fs_test_%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = first.pool.Exec(context.Background(), "DELETE FROM sso_member_identities WHERE subject=$1", subject)
	})
	want := feishu.Identity{OpenID: "ou_alice", Name: "Alice", TenantKey: "tenant-1"}
	if err := first.Upsert(ctx, subject, want); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	got, err := second.BySubject(ctx, subject)
	if err != nil || got != want {
		t.Fatalf("identity after reopen = %#v, %v; want %#v", got, err, want)
	}
	if _, err := second.BySubject(ctx, subject+"-missing"); err == nil {
		t.Fatal("missing subject resolved")
	}
}
