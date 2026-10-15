package claudecfg

import (
	"strings"
	"testing"
)

// Slice 4b1 invariant 6: expiry is milliseconds and refresh fields are irrelevant.
func TestAccessToken(t *testing.T) {
	for _, tt := range []struct {
		blob, token string
		expires     int64
		valid       bool
	}{
		{`{"claudeAiOauth":{"accessToken":"capture-access-private","expiresAt":1792070060001,"refreshToken":{}}}`, "capture-access-private", 1792070060001, true},
		{`{"claudeAiOauth":{}}`, "", 0, true},
		{`{"claudeAiOauth":{"AccessToken":"wrong-case","ExpiresAt":123}}`, "", 0, true},
		{`{"claudeAiOauth":{"accessToken":"","expiresAt":null}}`, "", 0, true},
		{`{"claudeAiOauth":{"accessToken":123}}`, "", 0, false},
		{`{"claudeAiOauth":{"accessToken":"capture-access-private","expiresAt":"1792070060001"}}`, "", 0, false},
		{`{"claudeAiOauth":null}`, "", 0, false}, {`null`, "", 0, false},
		{`{"capture-access-private":invalid}`, "", 0, false},
	} {
		token, expires, err := AccessToken([]byte(tt.blob))
		if (err == nil) != tt.valid || token != tt.token || expires != tt.expires || err != nil && strings.Contains(err.Error(), "private") {
			t.Fatal("wrong token extraction, expiry or private error")
		}
	}
}
