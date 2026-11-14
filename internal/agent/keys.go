package agent

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// defaultCredentialKeys is matched case-insensitively against JSON *key names*.
// It is deliberately a deny-by-default assertion applied to allow-listed seed
// files: the point is not to be exhaustive but to fail closed on anything
// credential-shaped that a registry entry forgot about.
//
// Bare "access" and "refresh" are deliberately absent: they appear in pi's
// oauth.json but are too generic to match safely against legitimate settings.
// Those files are simply never seeded.
var defaultCredentialKeys = map[string]bool{
	"apikey":        true,
	"apikeys":       true,
	"api_key":       true,
	"api_keys":      true,
	"apisecret":     true,
	"api_secret":    true,
	"secret":        true,
	"secrets":       true,
	"token":         true,
	"tokens":        true,
	"accesstoken":   true,
	"access_token":  true,
	"refreshtoken":  true,
	"refresh_token": true,
	"sessiontoken":  true,
	"session_token": true,
	"password":      true,
	"passwd":        true,
	"clientsecret":  true,
	"client_secret": true,
	"privatekey":    true,
	"private_key":   true,
	"credential":    true,
	"credentials":   true,
	"bearer":        true,
}

// Credential-shaped names are frequently namespaced by their provider:
// ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN, AWS_SECRET_ACCESS_KEY. Exact
// matching alone would seed those values verbatim, so a separator-normalised
// suffix check backs up the exact list. The suffixes are deliberately specific:
// a bare "token" or "key" suffix would strip ordinary settings such as
// maxTokens or keyboardShortcut.
var credentialKeySuffixes = []string{
	"apikey", "apikeys", "apisecret", "clientsecret", "privatekey",
	"accesstoken", "refreshtoken", "sessiontoken", "authtoken",
	"accesskey", "password", "passwd", "credential", "credentials",
	"secret", "secrets",
}

func credentialKey(key string) bool {
	lower := strings.ToLower(key)
	if defaultCredentialKeys[lower] {
		return true
	}
	normalised := strings.NewReplacer("_", "", "-", "", ".", "").Replace(lower)
	for _, suffix := range credentialKeySuffixes {
		if strings.HasSuffix(normalised, suffix) {
			return true
		}
	}
	return false
}

// CredentialKeyPaths returns the dotted paths of keys inside raw that look like
// credential material. A JSON syntax error is reported separately so the caller
// can distinguish "clean" from "unassayable".
func CredentialKeyPaths(raw []byte) ([]string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	var found []string
	walkJSON(v, "", func(path, key string) bool {
		if credentialKey(key) {
			found = append(found, path)
		}
		return false
	})
	sort.Strings(found)
	return found, nil
}

// StripCredentialKeysFromJSON removes every credential-shaped key from a JSON
// document and returns the rewritten bytes plus the paths that were removed.
func StripCredentialKeysFromJSON(raw []byte) ([]byte, []string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, nil, err
	}
	var removed []string
	walkJSON(v, "", func(path, key string) bool {
		if credentialKey(key) {
			removed = append(removed, path)
			return true // delete
		}
		return false
	})
	sort.Strings(removed)
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("re-encoding stripped JSON: %w", err)
	}
	return out, removed, nil
}

// walkJSON visits every object key. Returning true from fn deletes that key.
// Maps are reference types, so deletion mutates in place.
func walkJSON(v any, path string, fn func(path, key string) bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			kp := k
			if path != "" {
				kp = path + "." + k
			}
			if fn(kp, k) {
				delete(t, k)
				continue
			}
			walkJSON(val, kp, fn)
		}
	case []any:
		for i, val := range t {
			walkJSON(val, fmt.Sprintf("%s[%d]", path, i), fn)
		}
	}
}
