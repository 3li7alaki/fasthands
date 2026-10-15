package claudecfg

import (
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"

	"fasthands/internal/oauth"
)

func RotateLogin(blob []byte, t oauth.Tokens, nowMs int64) ([]byte, error) {
	var object, login map[string]json.RawMessage
	if json.Unmarshal(blob, &object) != nil || object == nil || json.Unmarshal(object["claudeAiOauth"], &login) != nil || login == nil {
		return nil, errors.New("invalid OAuth credentials")
	}
	// T3: reject overflow rather than silently storing an expired or negative deadline.
	expires := func(seconds int64) (json.RawMessage, error) {
		if seconds < 0 || nowMs < 0 || seconds > (math.MaxInt64-nowMs)/1000 {
			return nil, errors.New("invalid token expiry")
		}
		return json.Marshal(nowMs + seconds*1000)
	}
	expiry, err := expires(t.ExpiresIn)
	if err != nil || t.AccessToken == "" || t.ExpiresIn <= 0 {
		return nil, errors.New("invalid token expiry or access token")
	}
	login["expiresAt"] = expiry
	login["accessToken"], _ = json.Marshal(t.AccessToken)
	if t.RefreshToken != "" {
		login["refreshToken"], _ = json.Marshal(t.RefreshToken)
	}
	if t.RefreshExpiresIn != nil {
		login["refreshTokenExpiresAt"], err = expires(*t.RefreshExpiresIn)
		if err != nil {
			return nil, err
		}
	}
	// T3: an empty scope keeps stored scopes; Claude treats a login without
	// user:inference as not a claude.ai login, so never store an empty list.
	if scopes := strings.Fields(t.Scope); len(scopes) != 0 {
		login["scopes"], _ = json.Marshal(scopes)
	}
	object["claudeAiOauth"] = rawObject(login)
	return rawObject(object), nil
}

func rawObject(object map[string]json.RawMessage) []byte {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	data := []byte{'{'}
	for i, key := range keys {
		if i != 0 {
			data = append(data, ',')
		}
		encoded, _ := json.Marshal(key)
		data = append(data, encoded...)
		data = append(data, ':')
		// T3: json.Marshal compacts RawMessage and HTML-escapes strings; append validated values verbatim.
		data = append(data, object[key]...)
	}
	return append(data, '}')
}
