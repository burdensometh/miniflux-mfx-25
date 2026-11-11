// SPDX-FileCopyrightText: Copyright The Miniflux Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package ui // import "miniflux.app/v2/internal/ui"

import (
	"log/slog"
	"net/http"

	"miniflux.app/v2/internal/crypto"
	"miniflux.app/v2/internal/http/request"
	"miniflux.app/v2/internal/http/response"
)

func (h *handler) oauth2Redirect(w http.ResponseWriter, r *http.Request) {
	provider := request.RouteStringParam(r, "provider")
	if provider == "" {
		slog.Warn("Invalid or missing OAuth2 provider")
		response.HTMLRedirect(w, r, h.routePath("/"))
		return
	}

	authProvider, err := getOAuth2Manager(r.Context()).FindProvider(provider)
	if err != nil {
		slog.Error("Unable to initialize OAuth2 provider",
			slog.String("provider", provider),
			slog.Any("error", err),
		)
		response.HTMLRedirect(w, r, h.routePath("/"))
		return
	}

	// Bind the authorization request to this browser session: the state is
	// persisted in the session and must be presented unchanged by the
	// provider callback, which prevents cross-session login CSRF (e.g. an
	// attacker forcing a victim to link the attacker's identity).
	state := crypto.GenerateRandomStringHex(16)
	request.WebSession(r).SetOAuth2State(state)

	authURL := authProvider.Config().AuthCodeURL(state)

	response.HTMLRedirect(w, r, authURL)
}
