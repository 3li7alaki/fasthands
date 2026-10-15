package claudecfg

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"fasthands/internal/oauth"
)

// Slice 4b2 invariant 2: preserve every untouched raw value, including spelling and whitespace.
func TestRotateLogin(t *testing.T) {
	blob := []byte(`{"claudeAiOauth":{"accessToken":"old-private","refreshToken":"old-refresh-private","expiresAt":123,"refreshTokenExpiresAt":9007199254740993,"scopes":[ "old" ],"subscriptionType":"m\u0061x","unknown":{ "n":1.2300e+4, "html":"<keep>&" },"rateLimitTier":"max_5x","clientId":"custom"},"outer":{ "keep":9007199254740993 }}`)
	for _, sent := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "present"}[sent], func(t *testing.T) {
			tokens := oauth.Tokens{AccessToken: "new-access-private", ExpiresIn: 28800}
			if sent {
				seconds := int64(86400)
				tokens.RefreshToken, tokens.Scope, tokens.RefreshExpiresIn = "new-refresh-private", "user:profile user:inference", &seconds
			}
			rotated, err := RotateLogin(blob, tokens, 1792070000123)
			var old, got, oldLogin, login map[string]json.RawMessage
			if err != nil || json.Unmarshal(blob, &old) != nil || json.Unmarshal(rotated, &got) != nil || json.Unmarshal(old["claudeAiOauth"], &oldLogin) != nil || json.Unmarshal(got["claudeAiOauth"], &login) != nil {
				t.Fatal("rotation failed")
			}
			if string(login["accessToken"]) != `"new-access-private"` || string(login["expiresAt"]) != "1792098800123" || !bytes.Equal(old["outer"], got["outer"]) {
				t.Fatal("wrong access token, millisecond expiry or outer field")
			}
			for key, raw := range oldLogin {
				if key == "accessToken" || key == "expiresAt" || sent && (key == "refreshToken" || key == "refreshTokenExpiresAt" || key == "scopes") {
					continue
				}
				if !bytes.Equal(raw, login[key]) {
					t.Fatalf("rotation changed untouched %s", key)
				}
			}
			if sent && (string(login["refreshToken"]) != `"new-refresh-private"` || string(login["refreshTokenExpiresAt"]) != "1792156400123" || string(login["scopes"]) != `["user:profile","user:inference"]`) {
				t.Fatal("wrong refresh token, refresh expiry or scopes")
			}
			access, refresh, err := OAuthTokens(rotated)
			wantRefresh := "old-refresh-private"
			if sent {
				wantRefresh = "new-refresh-private"
			}
			if err != nil || access != tokens.AccessToken || refresh != wantRefresh {
				t.Fatal("rotated login is unreadable")
			}
		})
	}
	// An empty scope must keep stored scopes: Claude rejects a login without user:inference.
	var before map[string]json.RawMessage
	json.Unmarshal(blob, &before)
	var oldLogin map[string]json.RawMessage
	json.Unmarshal(before["claudeAiOauth"], &oldLogin)
	rotated, err := RotateLogin(blob, oauth.Tokens{AccessToken: "a", ExpiresIn: 1, Scope: " "}, 0)
	var object, login map[string]json.RawMessage
	json.Unmarshal(rotated, &object)
	json.Unmarshal(object["claudeAiOauth"], &login)
	if err != nil || len(oldLogin["scopes"]) == 0 || !bytes.Equal(login["scopes"], oldLogin["scopes"]) {
		t.Fatal("empty scope changed stored scopes")
	}
}

func TestRotateLoginInvalid(t *testing.T) {
	tokens := oauth.Tokens{AccessToken: "a", ExpiresIn: 1}
	for _, blob := range []string{`null`, `[]`, `{}`, `{"claudeAiOauth":null}`, `{"claudeAiOauth":42}`, `invalid-private`} {
		if _, err := RotateLogin([]byte(blob), tokens, 0); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("bad login accepted or exposed")
		}
	}
	for _, expiry := range []int64{-1, 0, math.MaxInt64} {
		bad := tokens
		bad.ExpiresIn = expiry
		if _, err := RotateLogin([]byte(credentials), bad, 1792070000000); err == nil {
			t.Fatal("invalid expiry accepted")
		}
	}
	before := []byte(credentials)
	for _, seconds := range []int64{-1, math.MaxInt64} {
		tokens.RefreshExpiresIn = &seconds
		if _, err := RotateLogin(before, tokens, 1000); err == nil || !reflect.DeepEqual(before, []byte(credentials)) {
			t.Fatal("invalid refresh expiry accepted or input changed")
		}
	}
}
