package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"agentbox/internal/agent"
)

// runImages builds the sandbox images from the Containerfiles in image/.
func runImages(args []string) int {
	if len(args) == 0 || args[0] != "build" {
		fmt.Fprintln(os.Stderr, "usage: agentbox images build [base opencode pi shell]")
		return 2
	}
	targets := args[1:]
	if len(targets) == 0 {
		targets = []string{"base", "opencode", "pi"}
	}

	if err := buildTargets(targets); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	return 0
}

func buildTargets(targets []string) error {
	dir, err := imageDir()
	if err != nil {
		return err
	}
	for _, t := range targets {
		dockerfile := filepath.Join(dir, "Containerfile."+t)
		if _, err := os.Stat(dockerfile); err != nil {
			return fmt.Errorf("no Containerfile for %q", t)
		}
		tag := agent.DefaultImage(t)

		var extra []string
		if t != "base" {
			extra = append(extra, "--build-arg", "BASE="+agent.DefaultImage("base"))
		}

		argv := append([]string{"build", "-t", tag, "-f", dockerfile}, extra...)
		argv = append(argv, dir)

		fmt.Fprintf(os.Stderr, "agentbox: building %s\n", tag)
		cmd := execCommand("podman", argv...)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("build failed for %s: %w", t, err)
		}
	}
	return nil
}

// imageDir locates the image/ directory: next to the executable, or in the
// module root when running from a source checkout.
func imageDir() (string, error) {
	if override := os.Getenv("AGENTBOX_IMAGE_DIR"); override != "" {
		return override, nil
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "image")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	// Fall back to the source tree relative to this file.
	_, file, _, ok := runtime.Caller(0)
	if ok {
		cand := filepath.Join(filepath.Dir(filepath.Dir(file)), "image")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("cannot locate the image directory; set AGENTBOX_IMAGE_DIR")
}
