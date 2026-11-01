package identity

import "testing"

func TestSubjectStableAndAppScoped(t *testing.T) {
	a, err := Subject("cli_test", "ou_alice")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Subject("cli_test", "ou_alice")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("same Feishu identity changed subject")
	}
	other, err := Subject("cli_test", "ou_bob")
	if err != nil {
		t.Fatal(err)
	}
	if a == other {
		t.Fatal("different members shared a subject")
	}
	otherApp, err := Subject("cli_other", "ou_alice")
	if err != nil {
		t.Fatal(err)
	}
	if a == otherApp {
		t.Fatal("different Feishu apps shared a subject")
	}
}

func TestSubjectRejectsMissingIdentity(t *testing.T) {
	if _, err := Subject("cli_test", ""); err == nil {
		t.Fatal("missing open_id accepted")
	}
	if _, err := Subject("", "ou_alice"); err == nil {
		t.Fatal("missing app_id accepted")
	}
}
