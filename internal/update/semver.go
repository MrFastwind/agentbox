package update

import (
	"fmt"
	"strconv"
	"strings"
)

// semver is the numeric part of a release tag. Prereleases are excluded by the
// resolver: an agent's "latest" must not become a beta because a tag sorts high.
type semver [3]int

func parseSemver(raw string) (semver, error) {
	s := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if strings.ContainsAny(s, "-+") {
		return semver{}, fmt.Errorf("%q is a prerelease or build tag", raw)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("%q is not a three-part version", raw)
	}
	var v semver
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, fmt.Errorf("%q is not a valid version: %q", raw, p)
		}
		v[i] = n
	}
	return v, nil
}

func (v semver) String() string {
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
}

func compareValues(a, b semver) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// Compare returns -1, 0 or 1 for a < b, a == b or a > b.
func Compare(a, b string) int {
	av, aerr := parseSemver(a)
	bv, berr := parseSemver(b)
	if aerr != nil || berr != nil {
		return strings.Compare(a, b)
	}
	return compareValues(av, bv)
}

// NewestTag returns the greatest stable tag in a release list.
func NewestTag(tags []string) (string, error) {
	var best string
	var bestV semver
	for _, tag := range tags {
		v, err := parseSemver(tag)
		if err != nil {
			continue
		}
		if best == "" || compareValues(v, bestV) > 0 {
			best, bestV = tag, v
		}
	}
	if best == "" {
		return "", fmt.Errorf("no stable release found")
	}
	return best, nil
}
