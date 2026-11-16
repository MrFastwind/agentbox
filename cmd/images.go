package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"agentbox/image"
	"agentbox/internal/agent"
)

// runImages builds the sandbox images from the Containerfiles compiled into the
// binary.
func runImages(args []string) int {
	if len(args) == 0 || args[0] != "build" {
		fmt.Fprintln(os.Stderr, "usage: agentbox images build [base opencode pi claude antigravity shell]")
		return 2
	}
	targets := args[1:]
	if len(targets) == 0 {
		targets = []string{"base", "opencode", "pi", "claude", "antigravity"}
	}

	if err := buildTargets(targets); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	return 0
}

func buildTargets(targets []string) error {
	dir, cleanup, err := imageSource()
	if err != nil {
		return err
	}
	defer cleanup()

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

// imageSource returns a directory holding every build input, plus the function
// that releases it.
//
// The default is the set embedded in the binary, staged into a temporary
// directory: podman needs a real path, and the base Containerfile COPYs
// entrypoint.sh from the build context. That keeps `images build` working from
// a lone executable with no checkout.
//
// A directory beside the executable is deliberately NOT discovered. Whatever
// happened to sit next to the binary would contribute RUN lines to a build the
// user believes came from the pinned, reviewed inputs; the explicit
// AGENTBOX_IMAGE_DIR override is the way to iterate on a Containerfile.
func imageSource() (string, func(), error) {
	if override := os.Getenv("AGENTBOX_IMAGE_DIR"); override != "" {
		return override, func() {}, nil
	}
	dir, err := os.MkdirTemp("", "agentbox-image-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("staging build inputs: %w", err)
	}
	cleanup := func() { os.RemoveAll(dir) }
	if err := stageImageInputs(dir); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return dir, cleanup, nil
}

func stageImageInputs(dir string) error {
	entries, err := fs.ReadDir(image.FS, ".")
	if err != nil {
		return fmt.Errorf("reading embedded build inputs: %w", err)
	}
	for _, e := range entries {
		data, err := image.FS.ReadFile(e.Name())
		if err != nil {
			return fmt.Errorf("reading embedded %s: %w", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o600); err != nil {
			return fmt.Errorf("staging %s: %w", e.Name(), err)
		}
	}
	return nil
}

// imageSourceName reports where a build would take its inputs from. It is shown
// by doctor because "built from the binary" and "built from a directory you
// pointed at" are different trust statements.
func imageSourceName() string {
	if override := os.Getenv("AGENTBOX_IMAGE_DIR"); override != "" {
		return "AGENTBOX_IMAGE_DIR=" + override
	}
	return "embedded in binary"
}
