package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/auth"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/provideraccess"
)

func grantRequest(s *Server, app, owner, method, body, id string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/", strings.NewReader(body))
	r.SetPathValue("id", app)
	r.SetPathValue("grantId", id)
	r = r.WithContext(auth.WithActor(r.Context(), auth.Actor{Name: owner, Kind: "service"}))
	w := httptest.NewRecorder()
	if method == "POST" {
		s.v1CreateProviderGrant(w, r)
	} else {
		s.v1DeleteProviderGrant(w, r)
	}
	return w
}

func TestProviderGrantAPIPermissionsAndRedaction(t *testing.T) {
	s, app := newConfigTestServer(t)
	body := `{"provider":"anthropic","config_key":"MODEL_KEY","ttl_seconds":3600}`
	if w := grantRequest(s, app, cfgTenant, "POST", body, ""); w.Code != 503 {
		t.Fatalf("disabled=%d", w.Code)
	}
	var err error
	s.ProviderAccess, err = provideraccess.New(s.Store, s.Secrets)
	if err != nil {
		t.Fatal(err)
	}
	if w := grantRequest(s, app, "other", "POST", body, ""); w.Code != 404 {
		t.Fatalf("owner=%d", w.Code)
	}
	if w := grantRequest(s, app, cfgTenant, "POST", body, ""); w.Code != 403 {
		t.Fatalf("no consent=%d", w.Code)
	}
	secret := "synthetic-do-not-disclose"
	w := do(s, "POST", "/v1/apps/"+app+"/config", `{"key":"MODEL_KEY","value":"`+secret+`","sensitive":true,"access_policy":"runtime_access"}`, cfgTenant, map[string]string{"id": app})
	if w.Code != 201 {
		t.Fatalf("config=%d %s", w.Code, w.Body)
	}
	for _, bad := range []string{body + `{}`, `{"provider":"anthropic","config_key":"MODEL_KEY","ttl_seconds":0}`, `{"provider":"anthropic","config_key":"MODEL_KEY","ttl_seconds":999999999999999999}`, `{"provider":"anthropic","config_key":"MODEL_KEY","ttl_seconds":60,"owner":"other"}`, strings.Repeat(" ", 4097) + body} {
		if w := grantRequest(s, app, cfgTenant, "POST", bad, ""); w.Code != 400 {
			t.Fatalf("invalid body=%d", w.Code)
		}
	}
	w = grantRequest(s, app, cfgTenant, "POST", body, "")
	if w.Code != 201 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), secret) {
		t.Fatalf("issue=%d %s", w.Code, w.Body)
	}
	var g struct{ ID, Token, BasePath string }
	var out map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	g.ID = out["id"]
	g.Token = out["token"]
	g.BasePath = out["base_path"]
	if len(g.Token) != 43 || g.BasePath != "/apps/"+app+"/anthropic" {
		t.Fatal("invalid grant response")
	}
	if w := grantRequest(s, app, "other", "DELETE", "", g.ID); w.Code != 404 {
		t.Fatalf("cross-owner revoke=%d", w.Code)
	}
	for i := 0; i < 2; i++ {
		if w := grantRequest(s, app, cfgTenant, "DELETE", "", g.ID); w.Code != http.StatusNoContent {
			t.Fatalf("revoke=%d", w.Code)
		}
	}
	r := httptest.NewRequest("POST", g.BasePath+"/v1/messages", nil)
	r.Header.Set("X-Api-Key", g.Token)
	w = httptest.NewRecorder()
	s.ProviderAccess.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("revoked grant=%d", w.Code)
	}
}
