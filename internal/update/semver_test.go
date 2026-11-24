package update

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{"older", "1.19.6", "2.4.1", -1},
		{"newer", "v2.4.1", "1.19.6", 1},
		{"equal with v", "v1.5.9", "1.5.9", 0},
		{"patch bump", "1.5.9", "1.5.16", -1},
		{"malformed falls back to lexical", "latest", "stable", -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Compare(tc.a, tc.b); got != tc.want {
				t.Fatalf("Compare(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestNewestTagSkipsPrereleasesAndMalformedTags(t *testing.T) {
	got, err := NewestTag([]string{"v1.19.6", "v9.9.9-beta.1", "nightly", "v2.4.1", "1.5.16"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "v2.4.1" {
		t.Fatalf("NewestTag = %q, want v2.4.1", got)
	}
	if _, err := NewestTag([]string{"nightly", "v1-beta"}); err == nil {
		t.Fatal("NewestTag accepted a list with no stable release")
	}
}

func TestParseSemverRejectsPrereleaseAndBuildTags(t *testing.T) {
	for _, raw := range []string{"1.2-beta", "1.2.3+build", "1.2", "1.2.x", "v1.2.-3"} {
		if _, err := parseSemver(raw); err == nil {
			t.Errorf("parseSemver accepted %q", raw)
		}
	}
	v, err := parseSemver(" v3.4.5 ")
	if err != nil || v.String() != "3.4.5" {
		t.Fatalf("parseSemver = (%v, %v)", v, err)
	}
}
