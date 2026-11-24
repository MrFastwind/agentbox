package cmd

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"agentbox/image"
	"agentbox/internal/agent"
	"agentbox/internal/policy"
	"agentbox/internal/update"
)

var newUpdateResolver = func() *update.Resolver { return update.NewResolver() }

const imagesUsage = `usage:
  agentbox images build [base opencode pi claude antigravity]
  agentbox images check [--agent NAME]
  agentbox images update [--agent NAME] [--dry-run]
  agentbox images rollback <agent> <version>`

// runImages builds, checks and installs sandbox images from the Containerfiles
// compiled into the binary. Agent updates are explicit: a normal run never
// resolves "latest".
func runImages(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, imagesUsage)
		return 2
	}
	switch args[0] {
	case "build":
		return runImagesBuild(args[1:])
	case "check":
		return runImagesCheck(args[1:])
	case "update":
		return runImagesUpdate(args[1:])
	case "rollback":
		return runImagesRollback(args[1:])
	default:
		fmt.Fprintln(os.Stderr, imagesUsage)
		return 2
	}
}

func runImagesBuild(args []string) int {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(os.Stderr, imagesUsage)
		return 0
	}
	if err := buildTargets(args); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	return 0
}

func buildTargets(targets []string) error {
	pins, err := loadPins()
	if err != nil {
		return err
	}
	return buildTargetsWithPins(targets, pins, nil)
}

func buildTargetsWithPins(targets []string, pins update.PinSet, versions map[string]string) error {
	if len(targets) == 0 {
		targets = []string{"base", "opencode", "pi", "claude", "antigravity"}
	}
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
		args := pins.ArgsFor(t)
		if args == nil {
			return fmt.Errorf("no pins for %q", t)
		}
		keys := make([]string, 0, len(args))
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			extra = append(extra, "--build-arg", k+"="+args[k])
		}

		if version := versions[t]; version != "" {
			if err := policy.ValidateAgentVersion(version); err != nil {
				return fmt.Errorf("agent %s: %w", t, err)
			}
			extra = append(extra, "-t", update.ImageRef(t, version))
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

func runImagesCheck(args []string) int {
	fs := flag.NewFlagSet("images check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	agentName := fs.String("agent", "", "check one agent")
	if err := fs.Parse(args); err != nil || len(fs.Args()) != 0 {
		fmt.Fprintln(os.Stderr, imagesUsage)
		return 2
	}
	pins, err := loadPins()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	state, err := update.LoadState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	targets, err := selectedTargets(pins, *agentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 2
	}
	resolver := newUpdateResolver()
	for _, target := range targets {
		candidate, err := resolver.Resolve(context.Background(), target, pins.Agents[target])
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: resolving %s: %v\n", target, err)
			return 1
		}
		current, installed := state.For(target)
		currentVersion := current.Version
		if !installed {
			currentVersion = pins.Agents[target].Version + " (embedded, not installed)"
		}
		fmt.Printf("%s: embedded=%s installed=%s available=%s\n", target, pins.Agents[target].Version, currentVersion, candidate.Version)
	}
	return 0
}

type imagePlan struct {
	target    string
	candidate update.AgentPin
	pins      update.PinSet
}

func runImagesUpdate(args []string) int {
	fs := flag.NewFlagSet("images update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	agentName := fs.String("agent", "", "update one agent")
	dryRun := fs.Bool("dry-run", false, "show what would be installed")
	if err := fs.Parse(args); err != nil || len(fs.Args()) != 0 {
		fmt.Fprintln(os.Stderr, imagesUsage)
		return 2
	}
	pins, err := loadPins()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	state, err := update.LoadState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	targets, err := selectedTargets(pins, *agentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 2
	}
	resolver := newUpdateResolver()
	var plans []imagePlan
	for _, target := range targets {
		candidate, err := resolver.Resolve(context.Background(), target, pins.Agents[target])
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: resolving %s: %v\n", target, err)
			return 1
		}
		next := pins.WithAgent(target, candidate)
		if err := next.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: refusing %s update: %v\n", target, err)
			return 1
		}
		current, installed := state.For(target)
		if installed && update.Compare(candidate.Version, current.Version) <= 0 {
			fmt.Fprintf(os.Stderr, "agentbox: %s already at %s\n", target, current.Version)
			continue
		}
		plans = append(plans, imagePlan{target: target, candidate: candidate, pins: next})
	}
	if len(plans) == 0 {
		fmt.Fprintln(os.Stderr, "agentbox: all selected agents are up to date")
		return 0
	}
	if *dryRun {
		for _, plan := range plans {
			fmt.Printf("would install %s %s as %s\n", plan.target, plan.candidate.Version, update.ImageRef(plan.target, plan.candidate.Version))
		}
		return 0
	}

	if !imageExists(agent.DefaultImage("base")) {
		if err := buildTargetsWithPins([]string{"base"}, pins, nil); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
			return 1
		}
	}
	for _, plan := range plans {
		imageRef := update.ImageRef(plan.target, plan.candidate.Version)
		if err := buildTargetsWithPins([]string{plan.target}, plan.pins, map[string]string{plan.target: plan.candidate.Version}); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
			return 1
		}
		rec := update.RecordFor(plan.target, plan.candidate, imageRef)
		if err := state.Set(plan.target, rec); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
			return 1
		}
		if err := update.SaveState(state); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
			return 1
		}
		fmt.Printf("installed %s %s as %s\n", plan.target, plan.candidate.Version, imageRef)
	}
	return 0
}

func runImagesRollback(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, imagesUsage)
		return 2
	}
	target, version := args[0], args[1]
	if err := policy.ValidateAgentVersion(version); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 2
	}
	pins, err := loadPins()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	if _, ok := pins.Agents[target]; !ok {
		fmt.Fprintf(os.Stderr, "agentbox: unknown agent %q\n", target)
		return 2
	}
	state, err := update.LoadState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	rec, ok := state.Historical(target, version)
	if !ok {
		fmt.Fprintf(os.Stderr, "agentbox: no recorded %s %s image\n", target, version)
		return 2
	}
	rollbackPins := pins.WithAgent(target, update.AgentPin{Version: rec.Version, Args: rec.Args, Source: rec.Source})
	if err := rollbackPins.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: refusing rollback: %v\n", err)
		return 1
	}
	if !imageExists(rec.Image) {
		if err := buildTargetsWithPins([]string{target}, rollbackPins, map[string]string{target: rec.Version}); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
			return 1
		}
	}
	cmd := execCommand("podman", "tag", rec.Image, update.LatestRef(target))
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: retagging %s: %v\n", rec.Image, err)
		return 1
	}
	rec.UpdatedAt = update.Timestamp()
	if err := state.Set(target, rec); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	if err := update.SaveState(state); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v\n", err)
		return 1
	}
	fmt.Printf("rolled back %s to %s (%s)\n", target, rec.Version, rec.Image)
	return 0
}

func selectedTargets(pins update.PinSet, requested string) ([]string, error) {
	if requested != "" {
		if _, ok := pins.Agents[requested]; !ok {
			return nil, fmt.Errorf("unknown agent %q", requested)
		}
		return []string{requested}, nil
	}
	targets := make([]string, 0, len(pins.Agents))
	for name := range pins.Agents {
		targets = append(targets, name)
	}
	sort.Strings(targets)
	return targets, nil
}

func loadPins() (update.PinSet, error) {
	return update.LoadPins(image.FS, "pins.yaml")
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
