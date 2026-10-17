package session

import (
	"errors"
	"os"
	"testing"

	"agentbox/internal/audit"
	"agentbox/internal/fsx"
	"agentbox/internal/policy"
)

// swapAfterResolve is a Fake whose EvalSymlinks reports a different path for the
// launch directory on the second look. Resolution validates the first path; the
// pre-run re-check (V4) sees the second — exactly the window a symlink swapped
// between the two checks would occupy.
type swapAfterResolve struct {
	*fsx.Fake
	target string
	seen   int
}

func (s *swapAfterResolve) EvalSymlinks(p string) (string, error) {
	if p == s.target {
		s.seen++
		if s.seen > 1 {
			return s.target + "-swapped", nil
		}
	}
	return s.Fake.EvalSymlinks(p)
}

func TestBootRefusesMountSwappedAfterResolution(t *testing.T) {
	withRun(t, func(*policy.ResolvedSpec, []string, *os.File, *os.File, *os.File) (int, error) {
		t.Fatal("a mount that changed after resolution must not run")
		return 1, nil
	})
	out, err := os.CreateTemp(t.TempDir(), "argv")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	o := Options{
		Resolver: policy.NewResolver(&swapAfterResolve{Fake: fakeHost(), target: testProject}, noEnv),
		Stdout:   out,
	}
	if _, err := o.Boot(baseDef(), policy.Request{LaunchDir: testProject}); err == nil {
		t.Fatal("expected the re-validation to refuse a swapped mount")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("audit sink is full") }

// A run whose decision cannot be recorded must not proceed: "if it is not in the
// audit log, it did not happen" cuts the other way too.
func TestBootAbortsWhenAuditFails(t *testing.T) {
	withRun(t, func(*policy.ResolvedSpec, []string, *os.File, *os.File, *os.File) (int, error) {
		t.Fatal("the run must be abandoned when the audit record cannot be written")
		return 1, nil
	})
	out, err := os.CreateTemp(t.TempDir(), "argv")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	o := options(fakeHost(), out)
	o.Audit = audit.New(failWriter{})
	if _, err := o.Boot(baseDef(), policy.Request{LaunchDir: testProject}); err == nil {
		t.Fatal("an audit failure must abort the run")
	}
}

func TestWriteSeedsReportsStagingErrors(t *testing.T) {
	t.Run("parent directory cannot be created", func(t *testing.T) {
		dir := t.TempDir()
		// A file where the seed's parent directory should go.
		if err := os.WriteFile(dir+"/blocker", []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := writeSeeds(dir, []policy.SeededFile{{Rel: "blocker/nested.json", Data: []byte("{}")}}); err == nil {
			t.Fatal("a seed whose parent directory cannot be created must be reported")
		}
	})
	t.Run("destination cannot be written", func(t *testing.T) {
		dir := t.TempDir()
		// A directory where the seed file should go.
		if err := os.Mkdir(dir+"/occupied", 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeSeeds(dir, []policy.SeededFile{{Rel: "occupied", Data: []byte("{}")}}); err == nil {
			t.Fatal("a seed whose destination cannot be written must be reported")
		}
	})
}
