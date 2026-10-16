package policy

import (
	"fmt"
	"regexp"
)

var (
	memoryRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?([bkmgBKMG])?$`)
	cpusRe   = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
)

const (
	defaultMemory = "4g"
	defaultCPUs   = "2"
	defaultPids   = 2048
	minPids       = 64
	maxPids       = 32768
)

// resolveLimits validates and clamps resource caps.
//
// Clamping rather than trusting matters because these values can arrive from a
// project configuration file, and an unbounded pids limit turns a fork bomb
// inside the sandbox into a host problem.
func resolveLimits(memory, cpus string, pids int) (Limits, []Refusal) {
	var refusals []Refusal
	l := Limits{Memory: defaultMemory, CPUs: defaultCPUs, Pids: defaultPids}

	if memory != "" {
		if !memoryRe.MatchString(memory) {
			refusals = append(refusals, warn(RefusalResource, "memory",
				fmt.Sprintf("unrecognised value %q; using %s", memory, defaultMemory)))
		} else {
			l.Memory = memory
		}
	}
	if cpus != "" {
		if !cpusRe.MatchString(cpus) {
			refusals = append(refusals, warn(RefusalResource, "cpus",
				fmt.Sprintf("unrecognised value %q; using %s", cpus, defaultCPUs)))
		} else {
			l.CPUs = cpus
		}
	}
	switch {
	case pids == 0:
		// keep default
	case pids < minPids:
		refusals = append(refusals, warn(RefusalResource, "pids-limit",
			fmt.Sprintf("%d is below the minimum %d; using %d", pids, minPids, minPids)))
		l.Pids = minPids
	case pids > maxPids:
		refusals = append(refusals, warn(RefusalResource, "pids-limit",
			fmt.Sprintf("%d is above the maximum %d; using %d", pids, maxPids, maxPids)))
		l.Pids = maxPids
	default:
		l.Pids = pids
	}
	return l, refusals
}
