package main

import (
	"bufio"
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chenyibo111/yb-sso/internal/feishu"
	"github.com/chenyibo111/yb-sso/internal/server"
	"github.com/chenyibo111/yb-sso/internal/session"
)

func loadLocalEnv(path string) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && os.Getenv(strings.TrimSpace(key)) == "" {
			_ = os.Setenv(strings.TrimSpace(key), strings.TrimSpace(value))
		}
	}
	return scanner.Err()
}

func main() {
	if err := loadLocalEnv(".env"); err != nil {
		log.Fatal(err)
	}
	member := feishu.Client{AppID: os.Getenv("FEISHU_APP_ID"), AppSecret: os.Getenv("FEISHU_APP_SECRET"), TenantKey: os.Getenv("FEISHU_TENANT_KEY")}
	if len(os.Getenv("SSO_SERVICE_KEY")) < 32 {
		log.Fatal("SSO_SERVICE_KEY must contain at least 32 characters")
	}
	if member.TenantKey == "" {
		log.Fatal("FEISHU_TENANT_KEY is required")
	}
	store, err := session.Open(context.Background(), os.Getenv("SSO_DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	verifier, err := session.NewVerifier(context.Background(), "http://localhost:4444/")
	if err != nil {
		log.Fatal(err)
	}
	sso, err := server.New(server.Config{
		AppID:         member.AppID,
		RedirectURI:   os.Getenv("FEISHU_REDIRECT_URI"),
		HydraAdminURL: "http://localhost:4445",
		Revocations:   store,
		TokenVerifier: verifier,
		ServiceKey:    os.Getenv("SSO_SERVICE_KEY"),
	}, member)
	if err != nil {
		log.Fatal(err)
	}
	httpServer := &http.Server{Addr: "127.0.0.1:9000", Handler: sso, ReadHeaderTimeout: 5 * time.Second}
	log.Println("Feishu SSO login service listening on http://localhost:9000")
	log.Fatal(httpServer.ListenAndServe())
}
