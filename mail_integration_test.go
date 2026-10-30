package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func apiRequest(method, path, body string) *http.Request {
	return httptest.NewRequest(method, "http://127.0.0.1:18765"+path, strings.NewReader(body))
}
func apiRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }
func mustJSON(value any) string               { raw, _ := json.Marshal(value); return string(raw) }

func TestPostgresDigestIdempotencyAndUncertainDelivery(t *testing.T) {
	store := integrationStore(t)
	ctx := context.Background()
	config := defaultSMTP()
	config.Host = "smtp.example.com"
	config.From = "owner@example.com"
	config.Recipients = []string{"member@example.com"}
	config.SendEmpty = true
	var mu sync.Mutex
	count := 0
	engine := &Engine{Store: store, SendMail: func(SMTPConfig, string, string) error { mu.Lock(); count++; mu.Unlock(); return nil }}
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := engine.sendDigest(ctx, config, true); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if count != 1 {
		t.Fatalf("SMTP called %d times", count)
	}
	config.Recipients = []string{"another@example.com"}
	if _, err := engine.sendDigest(ctx, config, true); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("recipient change bypassed daily dedupe")
	}
	config.ScopeIDs = []int64{12345}
	engine.SendMail = func(SMTPConfig, string, string) error {
		count++
		return &deliveryError{errors.New("fixture uncertain DATA response"), true}
	}
	if _, err := engine.sendDigest(ctx, config, true); err == nil {
		t.Fatal("uncertain delivery accepted as success")
	}
	engine.sendDigest(ctx, config, true)
	if count != 2 {
		t.Fatal("uncertain mail resent")
	}
	var status string
	store.DB.QueryRow(ctx, "SELECT status FROM digest_logs WHERE status='uncertain'").Scan(&status)
	if status != "uncertain" {
		t.Fatal("uncertain state not retained")
	}
}
func TestPostgresSMTPSecretMaskAndBlankPreservation(t *testing.T) {
	store := integrationStore(t)
	config := defaultSMTP()
	config.Host = "smtp.example.com"
	config.From = "owner@example.com"
	config.Recipients = []string{"member@example.com"}
	config.Password = "fixture-authorization-secret"
	if err := store.putSetting(context.Background(), "smtp", config); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{Store: store}
	r := apiRequest("GET", "/api/settings/smtp", "")
	w := apiRecorder()
	engine.serve(w, r, User{ID: 1, Role: "admin"})
	if w.Code != 200 || strings.Contains(w.Body.String(), config.Password) {
		t.Fatal("SMTP secret leaked")
	}
	config.Password = ""
	raw := mustJSON(config)
	r = apiRequest("PUT", "/api/settings/smtp", raw)
	w = apiRecorder()
	engine.serve(w, r, User{ID: 1, Role: "admin"})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var loaded SMTPConfig
	if err := store.setting(context.Background(), "smtp", &loaded); err != nil || loaded.Password != "fixture-authorization-secret" {
		t.Fatal("blank password overwrote saved key", err)
	}
}
