package update

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	defaultGitHubAPI   = "https://api.github.com"
	defaultNPMRegistry = "https://registry.npmjs.org"
)

var nodeMinimumPattern = regexp.MustCompile(`>=?\s*([0-9]+\.[0-9]+\.[0-9]+)`)

// Resolver turns upstream release metadata into exact, verified build pins.
// It does not decide whether an update is safe to run; it only reports what a
// release claims. Validation stays in policy and PinSet.Validate.
type Resolver struct {
	Client      *http.Client
	GitHubAPI   string
	NPMRegistry string
	Now         func() time.Time
}

// NewResolver returns a resolver using upstream endpoints.
func NewResolver() *Resolver {
	return &Resolver{
		Client:      &http.Client{Timeout: 30 * time.Second},
		GitHubAPI:   defaultGitHubAPI,
		NPMRegistry: defaultNPMRegistry,
		Now:         time.Now,
	}
}

type githubRelease struct {
	TagName    string        `json:"tag_name"`
	Prerelease bool          `json:"prerelease"`
	Draft      bool          `json:"draft"`
	HTMLURL    string        `json:"html_url"`
	Assets     []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
}

type npmPackage struct {
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
	Versions map[string]npmVersion `json:"versions"`
}

type npmVersion struct {
	Dist struct {
		Integrity string `json:"integrity"`
	} `json:"dist"`
	Engines map[string]string `json:"engines"`
}

// Resolve finds the newest stable release for target using current pins as the
// source for unchanged inputs such as the base image or Node runtime.
func (r *Resolver) Resolve(ctx context.Context, target string, current AgentPin) (AgentPin, error) {
	if r.Client == nil {
		return AgentPin{}, fmt.Errorf("update resolver has no http client")
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if current.Args == nil {
		current.Args = map[string]string{}
	}
	var pin AgentPin
	var err error
	switch target {
	case "opencode":
		pin, err = r.resolveGitHubMuslArtifact(ctx, "anomalyco/opencode", "opencode", current.Args)
	case "claude":
		pin, err = r.resolveGitHubMuslArtifact(ctx, "anthropics/claude-code", "claude", current.Args)
	case "antigravity":
		pin, err = r.resolveAntigravity(ctx, current.Args)
	case "pi":
		pin, err = r.resolvePi(ctx, current.Args)
	default:
		return AgentPin{}, fmt.Errorf("unknown update target %q", target)
	}
	if err != nil {
		return AgentPin{}, err
	}
	pin.ResolvedAt = r.Now().UTC().Format(time.RFC3339)
	return pin, nil
}

func (r *Resolver) resolveGitHubMuslArtifact(ctx context.Context, repo, prefix string, current map[string]string) (AgentPin, error) {
	release, err := r.latestGitHubRelease(ctx, repo)
	if err != nil {
		return AgentPin{}, err
	}
	version := strings.TrimPrefix(release.TagName, "v")
	args := map[string]string{
		strings.ToUpper(prefix) + "_VERSION":      version,
		strings.ToUpper(prefix) + "_SHA256_X64":   assetDigest(release, prefix+"-linux-x64-musl.tar.gz"),
		strings.ToUpper(prefix) + "_SHA256_ARM64": assetDigest(release, prefix+"-linux-arm64-musl.tar.gz"),
	}
	for _, suffix := range []string{"_SHA256_X64", "_SHA256_ARM64"} {
		key := strings.ToUpper(prefix) + suffix
		if !digestPattern.MatchString(args[key]) {
			return AgentPin{}, fmt.Errorf("release %s has no sha256 digest for %s", release.TagName, key)
		}
	}
	for k, v := range current {
		if strings.HasPrefix(k, alpineImageArg) {
			args[k] = v
		}
	}
	return AgentPin{Version: version, Args: args, Source: release.HTMLURL}, nil
}

func (r *Resolver) resolveAntigravity(ctx context.Context, current map[string]string) (AgentPin, error) {
	release, err := r.latestGitHubRelease(ctx, "google-antigravity/antigravity-cli")
	if err != nil {
		return AgentPin{}, err
	}
	args := map[string]string{
		"AGY_VERSION":      strings.TrimPrefix(release.TagName, "v"),
		"AGY_SHA256_X64":   assetDigest(release, "agy_cli_linux_x64_musl.tar.gz"),
		"AGY_SHA256_ARM64": assetDigest(release, "agy_cli_linux_arm64_musl.tar.gz"),
	}
	for _, key := range []string{"AGY_SHA256_X64", "AGY_SHA256_ARM64"} {
		if !digestPattern.MatchString(args[key]) {
			return AgentPin{}, fmt.Errorf("release %s has no sha256 digest for %s", release.TagName, key)
		}
	}
	for k, v := range current {
		if strings.HasPrefix(k, alpineImageArg) {
			args[k] = v
		}
	}
	return AgentPin{Version: args["AGY_VERSION"], Args: args, Source: release.HTMLURL}, nil
}

func (r *Resolver) resolvePi(ctx context.Context, current map[string]string) (AgentPin, error) {
	base := strings.TrimRight(r.NPMRegistry, "/")
	var pkg npmPackage
	if err := r.getJSON(ctx, base+"/@earendil-works%2fpi-coding-agent", &pkg); err != nil {
		return AgentPin{}, fmt.Errorf("reading pi release metadata: %w", err)
	}
	version := pkg.DistTags.Latest
	if _, err := parseSemver(version); err != nil {
		return AgentPin{}, fmt.Errorf("pi latest version %q is not stable: %w", version, err)
	}
	entry, ok := pkg.Versions[version]
	if !ok || entry.Dist.Integrity == "" {
		return AgentPin{}, fmt.Errorf("pi %s has no integrity metadata", version)
	}
	digest, err := integrityToHex(entry.Dist.Integrity)
	if err != nil {
		return AgentPin{}, fmt.Errorf("pi %s integrity: %w", version, err)
	}
	nodeVersion := current["NODE_VERSION"]
	if nodeVersion == "" {
		return AgentPin{}, fmt.Errorf("current node version is missing")
	}
	if min := nodeMinimumPattern.FindStringSubmatch(entry.Engines["node"]); len(min) == 2 {
		if Compare(nodeVersion, min[1]) < 0 {
			return AgentPin{}, fmt.Errorf("pi %s needs node >= %s, pins have %s", version, min[1], nodeVersion)
		}
	}
	args := map[string]string{"PI_VERSION": version, "PI_SHA512_HEX": digest}
	for _, k := range []string{alpineImageArg, "NODE_VERSION", "NODE_SHA256_X64", "NODE_SHA256_ARM64"} {
		if current[k] == "" {
			return AgentPin{}, fmt.Errorf("current %s is missing", k)
		}
		args[k] = current[k]
	}
	return AgentPin{Version: version, Args: args, Source: base + "/package/@earendil-works/pi-coding-agent"}, nil
}

func (r *Resolver) latestGitHubRelease(ctx context.Context, repo string) (githubRelease, error) {
	base := strings.TrimRight(r.GitHubAPI, "/")
	var releases []githubRelease
	if err := r.getJSON(ctx, fmt.Sprintf("%s/repos/%s/releases?per_page=100", base, repo), &releases); err != nil {
		return githubRelease{}, fmt.Errorf("reading %s releases: %w", repo, err)
	}
	tags := make([]string, 0, len(releases))
	byTag := make(map[string]githubRelease, len(releases))
	for _, rel := range releases {
		if rel.Draft || rel.Prerelease {
			continue
		}
		if _, err := parseSemver(rel.TagName); err != nil {
			continue
		}
		tags = append(tags, rel.TagName)
		byTag[rel.TagName] = rel
	}
	tag, err := NewestTag(tags)
	if err != nil {
		return githubRelease{}, fmt.Errorf("%s: %w", repo, err)
	}
	return byTag[tag], nil
}

func (r *Resolver) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := r.Client.Do(req)
	if err != nil {
		return fmt.Errorf("requesting %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("requesting %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding %s: %w", url, err)
	}
	return nil
}

func (r *Resolver) getText(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("requesting %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", url, err)
	}
	return string(body), nil
}

func assetURL(release githubRelease, name string) string {
	for _, asset := range release.Assets {
		if asset.Name == name {
			return asset.BrowserDownloadURL
		}
	}
	return ""
}

func assetDigest(release githubRelease, name string) string {
	for _, asset := range release.Assets {
		if asset.Name == name {
			return strings.TrimPrefix(asset.Digest, "sha256:")
		}
	}
	return ""
}

func parseChecksums(text string) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 {
			continue
		}
		if !digestPattern.MatchString(fields[0]) {
			return nil, fmt.Errorf("invalid digest %q", fields[0])
		}
		out[strings.TrimPrefix(fields[1], "*")] = fields[0]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no checksums found")
	}
	return out, nil
}

func integrityToHex(integrity string) (string, error) {
	algo, encoded, ok := strings.Cut(integrity, "-")
	if !ok || algo != "sha512" {
		return "", fmt.Errorf("unsupported integrity %q", integrity)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("decoding base64: %w", err)
		}
	}
	if len(raw) != 64 {
		return "", fmt.Errorf("expected 64 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}
