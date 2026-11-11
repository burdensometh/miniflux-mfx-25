// SPDX-FileCopyrightText: Copyright The Miniflux Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package ui // import "miniflux.app/v2/internal/ui"

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"miniflux.app/v2/internal/http/request"
	"miniflux.app/v2/internal/model"
)

func newOAuth2TestSession() *model.WebSession {
	session, _ := model.NewWebSession("test-agent", "127.0.0.1")
	return session
}

func requestWithSession(method, target string, session *model.WebSession) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	ctx := context.WithValue(r.Context(), request.WebSessionContextKey, session)
	return r.WithContext(ctx)
}

func TestOAuth2RedirectStoresStateInSession(t *testing.T) {
	configureTestOptions(t, map[string]string{
		"OAUTH2_PROVIDER":     "google",
		"OAUTH2_CLIENT_ID":    "client-id",
		"OAUTH2_REDIRECT_URL": "https://example.org/oauth2/google/callback",
	})

	h := &handler{basePath: ""}
	session := newOAuth2TestSession()

	r := requestWithSession(http.MethodGet, "/oauth2/google/redirect", session)
	r.SetPathValue("provider", "google")
	w := httptest.NewRecorder()

	h.oauth2Redirect(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf(`Unexpected status code, got: %d`, w.Code)
	}

	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf(`Redirect location is not a valid URL: %v`, err)
	}

	state := location.Query().Get("state")
	if state == "" {
		t.Fatal(`The authorization URL must carry a non-empty state parameter`)
	}

	if got := session.ConsumeOAuth2State(); got != state {
		t.Errorf(`Session state = %q, want %q`, got, state)
	}
}

func TestOAuth2RedirectRejectsUnknownProvider(t *testing.T) {
	configureTestOptions(t, map[string]string{"OAUTH2_PROVIDER": "google"})

	h := &handler{basePath: ""}
	session := newOAuth2TestSession()

	r := requestWithSession(http.MethodGet, "/oauth2/unknown/redirect", session)
	r.SetPathValue("provider", "unknown")
	w := httptest.NewRecorder()

	h.oauth2Redirect(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf(`Unexpected status code, got: %d`, w.Code)
	}

	if location := w.Header().Get("Location"); location != "/" {
		t.Errorf(`Unexpected redirect location, got: %q`, location)
	}
	if got := session.ConsumeOAuth2State(); got != "" {
		t.Errorf(`No state should be stored for an unknown provider, got: %q`, got)
	}
}

func TestOAuth2CallbackWithoutStateIsRejected(t *testing.T) {
	h := &handler{basePath: ""}
	session := newOAuth2TestSession()

	r := requestWithSession(http.MethodGet, "/oauth2/google/callback?code=some-code", session)
	r.SetPathValue("provider", "google")
	w := httptest.NewRecorder()

	h.oauth2Callback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf(`Unexpected status code, got: %d, want: %d`, w.Code, http.StatusBadRequest)
	}
	if got := session.ConsumeOAuth2State(); got != "" {
		t.Errorf(`No pending state should survive a rejected callback, got: %q`, got)
	}
}

func TestOAuth2CallbackWithForgedStateIsRejected(t *testing.T) {
	h := &handler{basePath: ""}
	session := newOAuth2TestSession()
	session.SetOAuth2State("expected-state")

	r := requestWithSession(http.MethodGet, "/oauth2/google/callback?code=some-code&state=forged-state", session)
	r.SetPathValue("provider", "google")
	w := httptest.NewRecorder()

	h.oauth2Callback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf(`Unexpected status code, got: %d, want: %d`, w.Code, http.StatusBadRequest)
	}

	// The pending state must be consumed on failure so the same forged
	// callback cannot be replayed.
	if got := session.ConsumeOAuth2State(); got != "" {
		t.Errorf(`The pending state must be consumed after a failed validation, got: %q`, got)
	}
}

func TestOAuth2CallbackStateIsSingleUse(t *testing.T) {
	configureTestOptions(t, map[string]string{
		"OAUTH2_PROVIDER":      "google",
		"OAUTH2_CLIENT_ID":     "client-id",
		"OAUTH2_CLIENT_SECRET": "client-secret",
		"OAUTH2_REDIRECT_URL":  "https://example.org/oauth2/google/callback",
	})

	h := &handler{basePath: ""}
	session := newOAuth2TestSession()
	session.SetOAuth2State("the-state")

	// A canceled context makes the provider fail locally (no network call)
	// only after state validation has passed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx = context.WithValue(ctx, request.WebSessionContextKey, session)

	r := httptest.NewRequest(http.MethodGet, "/oauth2/google/callback?code=some-code&state=the-state", nil).
		WithContext(ctx)
	r.SetPathValue("provider", "google")
	w := httptest.NewRecorder()

	h.oauth2Callback(w, r)

	// State validation passed: the request reached the provider exchange and
	// failed there, which redirects back to the login page.
	if w.Code != http.StatusFound {
		t.Fatalf(`Unexpected status code, got: %d, want: %d`, w.Code, http.StatusFound)
	}

	// Replaying the same callback with the same state must now be rejected.
	replay := requestWithSession(http.MethodGet, "/oauth2/google/callback?code=some-code&state=the-state", session)
	replay.SetPathValue("provider", "google")
	replayWriter := httptest.NewRecorder()

	h.oauth2Callback(replayWriter, replay)

	if replayWriter.Code != http.StatusBadRequest {
		t.Fatalf(`Replayed callback status = %d, want: %d`, replayWriter.Code, http.StatusBadRequest)
	}
}
