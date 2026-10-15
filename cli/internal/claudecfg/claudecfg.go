// Package claudecfg captures Claude Code's current credentials and account identity.
package claudecfg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"fasthands/internal/credstore"
)

type Capture struct {
	AccountUUID      string
	Email            string
	OrganizationUUID string
	OAuthAccount     json.RawMessage
	Credentials      []byte
}

func Service(raw string, set bool) (string, error) {
	const service = "Claude Code-credentials"
	// Claude Code treats an empty CLAUDE_CONFIG_DIR as unset, so it must not be hashed.
	if !set || raw == "" {
		return service, nil
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] >= 128 {
			// ponytail: stdlib has no NFC normalization; support non-ASCII only with an NFC implementation.
			return "", errors.New("CLAUDE_CONFIG_DIR must be ASCII for Keychain service hashing (NFC normalization unavailable)")
		}
	}
	hash := sha256.Sum256([]byte(raw))
	return service + "-" + hex.EncodeToString(hash[:4]), nil
}

func GlobalConfig(configHome, base string) string {
	modern := filepath.Join(configHome, ".config.json")
	legacy := filepath.Join(base, ".claude.json")
	info, err := os.Stat(modern)
	if err == nil && info.Mode().IsRegular() {
		if info.Size() > 0 {
			return modern
		}
		_, legacyErr := os.Stat(legacy)
		if info.Mode().Perm()&0222 != 0 && errors.Is(legacyErr, os.ErrNotExist) {
			return modern
		}
	}
	return legacy
}

func Read(platform, securityPath string) (Capture, error) {
	raw, set := os.LookupEnv("CLAUDE_CONFIG_DIR")
	base := raw
	configHome := raw
	if raw == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Capture{}, errors.New("cannot locate Claude Code home directory")
		}
		base, configHome = home, filepath.Join(home, ".claude")
	}
	path := filepath.Join(configHome, ".credentials.json")
	source := path
	var blob []byte
	var err error
	if platform == "darwin" {
		service, serviceErr := Service(raw, set)
		if serviceErr != nil {
			return Capture{}, serviceErr
		}
		current, userErr := user.Current()
		if userErr != nil {
			return Capture{}, errors.New("cannot determine current Keychain username")
		}
		blob, err = (credstore.Keychain{SecurityPath: securityPath}).Read(current.Username, service)
		if err != nil && !errors.Is(err, credstore.ErrAbsent) {
			return Capture{}, err
		}
		if err == nil {
			source = "Keychain service " + service
		}
	}
	if platform != "darwin" || errors.Is(err, credstore.ErrAbsent) {
		blob, err = os.ReadFile(path)
		if err != nil {
			return Capture{}, fmt.Errorf("cannot read credentials at %q", path)
		}
	}
	owned, err := accountCredentials(blob)
	if err != nil {
		return Capture{}, fmt.Errorf("invalid Claude Code login at %q", source)
	}
	global := GlobalConfig(configHome, base)
	data, err := os.ReadFile(global)
	if err != nil {
		return Capture{}, fmt.Errorf("cannot read global config at %q", global)
	}
	// Maps preserve Claude's case-sensitive property lookup; struct decoding folds case.
	var config, identity map[string]json.RawMessage
	if json.Unmarshal(data, &config) != nil || json.Unmarshal(config["oauthAccount"], &identity) != nil {
		return Capture{}, fmt.Errorf("invalid oauthAccount in global config at %q (accountUuid required)", global)
	}
	id, idOK := stringField(identity, "accountUuid")
	email, emailOK := stringField(identity, "emailAddress")
	org, orgOK := stringField(identity, "organizationUuid")
	if !idOK || id == "" || !emailOK || !orgOK {
		return Capture{}, fmt.Errorf("invalid oauthAccount in global config at %q (accountUuid required)", global)
	}
	return Capture{id, email, org, config["oauthAccount"], owned}, nil
}

func accountCredentials(blob []byte) ([]byte, error) {
	var object, oauth map[string]json.RawMessage
	if json.Unmarshal(blob, &object) != nil || object == nil ||
		json.Unmarshal(object["claudeAiOauth"], &oauth) != nil {
		return nil, errors.New("invalid OAuth credentials")
	}
	access, accessOK := stringField(oauth, "accessToken")
	refresh, refreshOK := stringField(oauth, "refreshToken")
	if !accessOK || !refreshOK || access == "" || refresh == "" {
		return nil, errors.New("invalid OAuth credentials")
	}
	for _, key := range []string{"mcpOAuth", "mcpOAuthClientConfig", "mcpXaaIdp", "mcpXaaIdpConfig", "pluginSecrets"} {
		delete(object, key)
	}
	return json.Marshal(object)
}

func stringField(object map[string]json.RawMessage, key string) (string, bool) {
	raw, exists := object[key]
	if !exists {
		return "", true
	}
	var value string
	err := json.Unmarshal(raw, &value)
	return value, err == nil
}
