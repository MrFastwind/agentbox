package agent

import "bytes"

// Transform rewrites a seed file's bytes on the way into the sandbox. It is how
// honesty about borrowed configuration is encoded: a file may be seeded if the
// credential material inside it is provably removed first.
type Transform interface {
	Name() string
	Apply(raw []byte) (out []byte, removed []string, err error)
}

// Identity seeds the file unchanged.
type Identity struct{}

func (Identity) Name() string { return "identity" }

func (Identity) Apply(raw []byte) ([]byte, []string, error) { return raw, nil, nil }

// StripCredentialKeys removes credential-shaped JSON keys, keeping the rest of
// the file. This is what makes settings.json and models.json seedable without
// handing the sandbox a live provider key: pi's own migration writes
// settings.apiKeys, and models.json carries providers.<id>.apiKey.
//
// Non-JSON input is passed through untouched; the content assertion in
// internal/policy is what catches unassayable files.
type StripCredentialKeys struct{}

func (StripCredentialKeys) Name() string { return "strip-credential-keys" }

func (StripCredentialKeys) Apply(raw []byte) ([]byte, []string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return raw, nil, nil
	}
	return StripCredentialKeysFromJSON(raw)
}
