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
	"regexp"

	"fasthands/internal/credstore"
	"fasthands/internal/statehome"
)

type Capture struct {
	AccountUUID      string
	Email            string
	OrganizationUUID string
	OAuthAccount     json.RawMessage
	Credentials      []byte
	SubscriptionType string
	RateLimitTier    string
}

type Locations struct {
	ConfigHome      string
	Base            string
	StorageDir      string
	Service         string
	KeychainAccount string
	CredentialsFile string
	GlobalConfig    string
}

var keychainAccountPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func Locate() (Locations, error) {
	raw, set := os.LookupEnv("CLAUDE_CONFIG_DIR")
	secure, secureSet := os.LookupEnv("CLAUDE_SECURESTORAGE_CONFIG_DIR")
	account := os.Getenv("USER")
	var home string
	if raw == "" || secureSet && secure == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return Locations{}, errors.New("cannot locate Claude Code home directory")
		}
	}
	loc := Locations{ConfigHome: raw, Base: raw}
	if raw == "" {
		loc.ConfigHome, loc.Base = filepath.Join(home, ".claude"), home
	}
	loc.StorageDir = loc.ConfigHome
	hashValue, hashSet, hashEnv := raw, set, "CLAUDE_CONFIG_DIR"
	if secureSet {
		loc.StorageDir = secure
		if secure == "" {
			loc.StorageDir = filepath.Join(home, ".claude")
		}
		hashValue, hashSet, hashEnv = secure, true, "CLAUDE_SECURESTORAGE_CONFIG_DIR"
	}
	service, err := serviceName(hashValue, hashSet, hashEnv)
	if err != nil {
		return Locations{}, err
	}
	if account == "" {
		if current, err := user.Current(); err == nil {
			account = current.Username
		}
	}
	if !keychainAccountPattern.MatchString(account) {
		account = "claude-code-user"
	}
	loc.Service, loc.KeychainAccount = service, account
	loc.CredentialsFile = filepath.Join(loc.StorageDir, ".credentials.json")
	loc.GlobalConfig = GlobalConfig(loc.ConfigHome, loc.Base)
	return loc, nil
}

func Service(raw string, set bool) (string, error) {
	return serviceName(raw, set, "CLAUDE_CONFIG_DIR")
}

func serviceName(raw string, set bool, env string) (string, error) {
	const service = "Claude Code-credentials"
	// L3: an explicitly empty secure-storage override also selects the unsuffixed service.
	if !set || raw == "" {
		return service, nil
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] >= 128 {
			// ponytail: stdlib has no NFC normalization; support non-ASCII only with an NFC implementation.
			return "", fmt.Errorf("%s must be ASCII for Keychain service hashing (NFC normalization unavailable)", env)
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
	loc, err := Locate()
	if err != nil {
		return Capture{}, err
	}
	blob, inKeychain, err := ReadLive(loc, platform, securityPath)
	if err != nil {
		return Capture{}, err
	}
	source := loc.CredentialsFile
	if inKeychain {
		source = "Keychain service " + loc.Service
	}
	owned, err := accountCredentials(blob)
	if err != nil {
		return Capture{}, fmt.Errorf("invalid Claude Code login at %q", source)
	}
	global := loc.GlobalConfig
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
	subscription, tier := Plan(blob)
	return Capture{id, email, org, config["oauthAccount"], owned, subscription, tier}, nil
}

// Plan reads only U4's public strings; credentials never enter account metadata.
func Plan(blob []byte) (subscription, tier string) {
	var object, oauth map[string]json.RawMessage
	if json.Unmarshal(blob, &object) == nil && json.Unmarshal(object["claudeAiOauth"], &oauth) == nil {
		subscription, _ = stringField(oauth, "subscriptionType")
		tier, _ = stringField(oauth, "rateLimitTier")
	}
	return
}

// ActiveUUID reads only the global config, keeping passive commands away from credentials.
func ActiveUUID(loc Locations) (string, error) {
	data, err := os.ReadFile(loc.GlobalConfig)
	if err != nil {
		return "", fmt.Errorf("cannot read global config at %q", loc.GlobalConfig)
	}
	var config, identity map[string]json.RawMessage
	var id string
	if json.Unmarshal(data, &config) != nil || json.Unmarshal(config["oauthAccount"], &identity) != nil ||
		json.Unmarshal(identity["accountUuid"], &id) != nil || id == "" {
		return "", fmt.Errorf("invalid oauthAccount in global config at %q (accountUuid required)", loc.GlobalConfig)
	}
	return id, nil
}

func accountCredentials(blob []byte) ([]byte, error) {
	access, refresh, err := OAuthTokens(blob)
	if err != nil || access == "" || refresh == "" {
		return nil, errors.New("invalid OAuth credentials")
	}
	return OwnedCredentials(blob)
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

func ReadLive(loc Locations, platform, securityPath string) ([]byte, bool, error) {
	if platform == "darwin" {
		blob, err := (credstore.Keychain{SecurityPath: securityPath}).ReadService(loc.KeychainAccount, loc.Service)
		if !errors.Is(err, credstore.ErrAbsent) {
			return blob, err == nil, err
		}
	}
	// F2: only an absent Keychain item permits the macOS file fallback.
	blob, err := os.ReadFile(loc.CredentialsFile)
	if err != nil {
		return nil, false, fmt.Errorf("cannot read credentials at %q", loc.CredentialsFile)
	}
	return blob, false, nil
}

func WriteLive(loc Locations, platform, securityPath string, inKeychain bool, blob []byte) error {
	if platform == "darwin" && inKeychain {
		return (credstore.Keychain{SecurityPath: securityPath}).WriteLive(loc.KeychainAccount, loc.Service, blob)
	}
	if err := statehome.ReplaceFile(loc.CredentialsFile, blob); err != nil {
		return fmt.Errorf("cannot write credentials at %q", loc.CredentialsFile)
	}
	return nil
}

// OAuthTokens permits empty tokens so switch can recognize Claude's wiped login (F5).
func OAuthTokens(blob []byte) (access, refresh string, err error) {
	var object, oauth map[string]json.RawMessage
	if json.Unmarshal(blob, &object) != nil || object == nil ||
		json.Unmarshal(object["claudeAiOauth"], &oauth) != nil || oauth == nil {
		return "", "", errors.New("invalid OAuth credentials")
	}
	access, accessOK := stringField(oauth, "accessToken")
	refresh, refreshOK := stringField(oauth, "refreshToken")
	if !accessOK || !refreshOK {
		return "", "", errors.New("invalid OAuth credentials")
	}
	return access, refresh, nil
}

var sharedKeys = []string{"mcpOAuth", "mcpOAuthClientConfig", "mcpXaaIdp", "mcpXaaIdpConfig", "pluginSecrets"}

func stripShared(object map[string]json.RawMessage) {
	for _, key := range sharedKeys {
		delete(object, key)
	}
}

func OwnedCredentials(blob []byte) ([]byte, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(blob, &object) != nil || object == nil {
		return nil, errors.New("invalid OAuth credentials")
	}
	stripShared(object)
	return json.Marshal(object)
}

func MergeCredentials(target, live []byte) ([]byte, error) {
	var object, machine map[string]json.RawMessage
	if json.Unmarshal(target, &object) != nil || object == nil || json.Unmarshal(live, &machine) != nil || machine == nil {
		return nil, errors.New("invalid OAuth credentials")
	}
	// F4: absence in the live object wins too; stale shared keys must disappear.
	stripShared(object)
	for _, key := range sharedKeys {
		if value, exists := machine[key]; exists {
			object[key] = value
		}
	}
	return json.Marshal(object)
}
