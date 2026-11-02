package session

import (
	"context"
	"errors"

	"github.com/chenyibo111/yb-sso/internal/feishu"
)

func (s *Store) Upsert(ctx context.Context, subject string, member feishu.Identity) error {
	if subject == "" || member.OpenID == "" || member.TenantKey == "" {
		return errors.New("incomplete member identity")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO sso_member_identities (subject, open_id, display_name, tenant_key)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (subject) DO UPDATE SET open_id=EXCLUDED.open_id,
		display_name=EXCLUDED.display_name, tenant_key=EXCLUDED.tenant_key, updated_at=now()`,
		subject, member.OpenID, member.Name, member.TenantKey)
	return err
}

func (s *Store) BySubject(ctx context.Context, subject string) (feishu.Identity, error) {
	if subject == "" {
		return feishu.Identity{}, errors.New("missing subject")
	}
	var member feishu.Identity
	err := s.pool.QueryRow(ctx, `SELECT open_id, display_name, tenant_key FROM sso_member_identities WHERE subject=$1`, subject).
		Scan(&member.OpenID, &member.Name, &member.TenantKey)
	return member, err
}
