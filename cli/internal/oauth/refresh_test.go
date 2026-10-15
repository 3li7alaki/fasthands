package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

const refreshPrivate = "oauth-refresh-distinctive-private"
const rotatedPrivate = "oauth-rotated-distinctive-private"

func refreshClient(t *testing.T, handler http.HandlerFunc) Client {
	t.Helper()
	c := testClient(t, handler)
	c.TokenURL = "https://token.test/v1/oauth/token"
	return c
}

// Slice 4b2 invariant 1: exact T1 payload, headers, omitted scope, and 15s deadline.
func TestRefreshRequest(t *testing.T) {
	calls := 0
	c := refreshClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, err := io.ReadAll(r.Body)
		want := `{"grant_type":"refresh_token","refresh_token":"` + refreshPrivate + `","client_id":"9d1c250a-e61b-44d9-88ed-5944d1962f5e"}`
		deadline, ok := r.Context().Deadline()
		if err != nil || string(body) != want || r.Method != "POST" || r.URL.String() != "https://token.test/v1/oauth/token" ||
			r.Header.Get("Content-Type") != "application/json" || r.UserAgent() != "fasthands/dev" || r.Header.Get("Authorization") != "" ||
			!ok || time.Until(deadline) <= 0 || time.Until(deadline) > 15*time.Second {
			t.Error("wrong token request, headers or timeout")
		}
		io.WriteString(w, `{"access_token":"`+privateToken+`","refresh_token":"`+rotatedPrivate+`","expires_in":28800,"refresh_token_expires_in":31536000,"scope":"user:profile user:inference","account":{"uuid":"id-b"},"future":true}`)
	})
	tokens, err := c.Refresh(context.Background(), refreshPrivate)
	if err != nil || calls != 1 || tokens.AccessToken != privateToken || tokens.RefreshToken != rotatedPrivate || tokens.ExpiresIn != 28800 || tokens.RefreshExpiresIn == nil || *tokens.RefreshExpiresIn != 31536000 || tokens.Scope != "user:profile user:inference" || tokens.AccountUUID != "id-b" || !tokens.AccountUUIDPresent {
		t.Fatal("wrong parsed refresh tokens")
	}
}

// Slice 4b2 invariants 7, 8, 10: T4 classification never exposes bodies or headers.
func TestRefreshFailures(t *testing.T) {
	for _, status := range []int{200, 400, 401, 403, 429, 500} {
		for _, code := range []string{"invalid_grant", "invalid_client", "other"} {
			t.Run(http.StatusText(status)+"/"+code, func(t *testing.T) {
				c := refreshClient(t, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Private", refreshPrivate)
					w.WriteHeader(status)
					io.WriteString(w, `{"error":"`+code+`","description":"`+refreshPrivate+privateToken+rotatedPrivate+`"}`)
				})
				_, err := c.Refresh(context.Background(), refreshPrivate)
				dead := (status == 400 || status == 401 || status == 403) && code == "invalid_grant"
				if err == nil || strings.Contains(err.Error(), "private") || errors.Is(err, ErrInvalidGrant) != dead {
					t.Fatal("wrong refresh classification or private error")
				}
			})
		}
	}
}

func TestRefreshInvalidAndBoundedResponse(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `broken-private`, `{} {}`, `{}`, `{"access_token":"a"}`, `{"expires_in":42}`,
		`{"access_token":"a","expires_in":null}`, `{"access_token":"a","expires_in":"42"}`, `{"access_token":"a","expires_in":0.5}`,
		`{"access_token":"a","expires_in":0}`, `{"access_token":"a","expires_in":-1}`, `{"access_token":42,"expires_in":42}`,
		`{"access_token":"` + strings.Repeat("x", 1<<20) + `","expires_in":42}`} {
		c := refreshClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
		if _, err := c.Refresh(context.Background(), refreshPrivate); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("invalid response accepted or exposed")
		}
	}
	c := refreshClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat(" ", 2<<20)) })
	var read int
	c.HTTP.Transport = bodyTransport{c.HTTP.Transport, &read}
	if _, err := c.Refresh(context.Background(), refreshPrivate); err == nil || read > 1<<20 {
		t.Fatal("refresh exceeded 1 MiB response cap")
	}
	// The token is rotated once the server answers: odd optional fields must never fail the parse.
	for _, body := range []string{`{"access_token":"a","expires_in":42}`, `{"access_token":"a","expires_in":42,"scope":""}`,
		`{"access_token":"a","expires_in":42.9,"scope":5,"refresh_token":7,"refresh_token_expires_in":"x","account":"x"}`,
		`{"access_token":"a","expires_in":42,"account":null,"refresh_token_expires_in":-1}`} {
		c := refreshClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
		tokens, err := c.Refresh(context.Background(), refreshPrivate)
		if err != nil || !reflect.DeepEqual(tokens, Tokens{AccessToken: "a", ExpiresIn: 42}) {
			t.Fatalf("lenient optional fields rejected or misread: %s", body)
		}
	}
	c = refreshClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"access_token":"a","expires_in":42,"account":{"uuid":5}}`)
	})
	if tokens, err := c.Refresh(context.Background(), refreshPrivate); err != nil || !tokens.AccountUUIDPresent || tokens.AccountUUID != "" {
		t.Fatal("unreadable account uuid must still count as present for R6")
	}
}

func TestRefreshTransportAndRedirect(t *testing.T) {
	calls := 0
	c := refreshClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, "/"+refreshPrivate, http.StatusTemporaryRedirect)
	})
	if _, err := c.Refresh(context.Background(), refreshPrivate); err == nil || calls != 1 || strings.Contains(err.Error(), "private") {
		t.Fatal("redirect followed or exposed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.TokenURL += "/" + refreshPrivate
	if _, err := c.Refresh(ctx, refreshPrivate); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("transport failure exposed request details")
	}
	c.TokenURL = ":" + refreshPrivate
	if _, err := c.Refresh(context.Background(), refreshPrivate); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("invalid URL exposed request details")
	}
}

type refreshErrorTransport bool

func (readFailure refreshErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if readFailure {
		return &http.Response{StatusCode: 200, Body: refreshErrorBody{}}, nil
	}
	return nil, errors.New(refreshPrivate + privateToken + rotatedPrivate)
}

type refreshErrorBody struct{}

func (refreshErrorBody) Read([]byte) (int, error) {
	return 0, errors.New(refreshPrivate + privateToken + rotatedPrivate)
}

func (refreshErrorBody) Close() error { return nil }

// Slice 4b2 invariant 10: neither transport nor response-read errors expose private details.
func TestRefreshIOErrors(t *testing.T) {
	for _, readFailure := range []refreshErrorTransport{false, true} {
		c := Client{TokenURL: "https://token.test", HTTP: &http.Client{Transport: readFailure}}
		if _, err := c.Refresh(context.Background(), refreshPrivate); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("I/O failure exposed private details")
		}
	}
}
