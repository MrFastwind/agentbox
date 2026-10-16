package cmd

import "strings"

// stringSlice is a repeatable string flag (--env, --mount).
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }

func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}
