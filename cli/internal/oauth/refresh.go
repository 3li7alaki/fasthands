package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

type Tokens struct {
	AccessToken, RefreshToken, Scope string
	ExpiresIn                        int64
	RefreshExpiresIn                 *int64
	AccountUUID                      string
	AccountUUIDPresent               bool // R6: an explicitly empty UUID also differs from a stored account.
}

var ErrInvalidGrant = errors.New("stored login expired")

func (c Client) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	// T1: bound time spent holding accounts.lock, including reading the response.
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	data, _ := json.Marshal(struct {
		GrantType    string `json:"grant_type"`
		RefreshToken string `json:"refresh_token"`
		ClientID     string `json:"client_id"`
	}{"refresh_token", refreshToken, "9d1c250a-e61b-44d9-88ed-5944d1962f5e"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, bytes.NewReader(data))
	if err != nil {
		return Tokens{}, errors.New("cannot create token refresh request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent) // T1: keep our requests separate from Claude's.
	httpClient := http.Client{}
	if c.HTTP != nil {
		httpClient = *c.HTTP
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpClient.Do(req)
	if err != nil {
		return Tokens{}, errors.New("cannot request token refresh") // T4: transport errors may contain credentials.
	}
	defer response.Body.Close()
	const limit = 1 << 20
	data, err = io.ReadAll(io.LimitReader(response.Body, limit))
	if err != nil || len(data) == limit {
		return Tokens{}, errors.New("cannot read token refresh response")
	}
	if response.StatusCode != http.StatusOK {
		var body map[string]json.RawMessage
		var code string
		if json.Unmarshal(data, &body) == nil {
			json.Unmarshal(body["error"], &code)
		}
		// T4: only these statuses with invalid_grant prove dead lineage.
		if (response.StatusCode == 400 || response.StatusCode == 401 || response.StatusCode == 403) && code == "invalid_grant" {
			return Tokens{}, ErrInvalidGrant
		}
		return Tokens{}, fmt.Errorf("token refresh request returned HTTP %d", response.StatusCode)
	}
	// The token is already rotated server side: only the two required fields may fail the
	// parse, and numbers are read as floats like Claude's Number(), so an odd optional
	// field can never discard the only copy of the new login.
	var body map[string]json.RawMessage
	var access string
	var expires float64
	if json.Unmarshal(data, &body) != nil || json.Unmarshal(body["access_token"], &access) != nil ||
		json.Unmarshal(body["expires_in"], &expires) != nil || access == "" || expires < 1 {
		return Tokens{}, errors.New("invalid token refresh response")
	}
	t := Tokens{AccessToken: access, ExpiresIn: seconds(expires)}
	json.Unmarshal(body["refresh_token"], &t.RefreshToken)
	json.Unmarshal(body["scope"], &t.Scope)
	var refreshExpires float64
	if json.Unmarshal(body["refresh_token_expires_in"], &refreshExpires) == nil && refreshExpires >= 0 {
		value := seconds(refreshExpires)
		t.RefreshExpiresIn = &value
	}
	var account map[string]json.RawMessage
	if json.Unmarshal(body["account"], &account) == nil && account != nil {
		if raw, ok := account["uuid"]; ok {
			t.AccountUUIDPresent = true // R6: a present but unreadable uuid still differs.
			json.Unmarshal(raw, &t.AccountUUID)
		}
	}
	return t, nil
}

// seconds saturates instead of converting out of range: RotateLogin then rejects the
// overflow with the log-in-again guidance a rotated, unsavable login needs (R4).
func seconds(value float64) int64 {
	if value >= 1<<62 {
		return math.MaxInt64
	}
	return int64(value)
}
