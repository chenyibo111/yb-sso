package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// Subject is stable for one user of one Feishu custom app.
func Subject(appID, openID string) (string, error) {
	if strings.TrimSpace(appID) == "" || strings.TrimSpace(openID) == "" {
		return "", errors.New("missing Feishu identity")
	}
	sum := sha256.Sum256([]byte(appID + "\x00" + openID))
	return "fs_" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
