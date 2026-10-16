package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// FakeEntry describes one node in a Fake filesystem.
type FakeEntry struct {
	Dir     bool
	Symlink string // target; empty means not a symlink
	Data    []byte
	Mode    os.FileMode
}

// Fake is an in-memory FS used by the policy tests. Paths are clean, absolute,
// slash-separated; ancestors are created on demand.
type Fake struct {
	Home  string
	Cwd   string
	Paths map[string]FakeEntry
}

func NewFake(home, cwd string) *Fake {
	return &Fake{Home: home, Cwd: cwd, Paths: map[string]FakeEntry{}}
}

// Mkdir records a directory and any missing ancestors.
func (f *Fake) Mkdir(p string) {
	p = path.Clean(p)
	f.Paths[p] = FakeEntry{Dir: true, Mode: 0o755}
	for dir := path.Dir(p); dir != "/" && dir != "."; dir = path.Dir(dir) {
		if _, ok := f.Paths[dir]; !ok {
			f.Paths[dir] = FakeEntry{Dir: true, Mode: 0o755}
		}
	}
}

// Write records a file, creating its parent directory.
func (f *Fake) Write(p string, data []byte) {
	p = path.Clean(p)
	f.Mkdir(path.Dir(p))
	f.Paths[p] = FakeEntry{Data: data, Mode: 0o600}
}

// Symlink records a symlink at p pointing at target.
func (f *Fake) Symlink(target, p string) {
	p = path.Clean(p)
	f.Mkdir(path.Dir(p))
	f.Paths[p] = FakeEntry{Symlink: target}
}

func (f *Fake) Abs(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if !strings.HasPrefix(p, "/") {
		p = path.Join(f.Cwd, p)
	}
	return path.Clean(p), nil
}

func (f *Fake) UserHomeDir() (string, error) { return f.Home, nil }
func (f *Fake) Getwd() (string, error)       { return f.Cwd, nil }

func (f *Fake) ReadFile(p string) ([]byte, error) {
	rp, err := f.EvalSymlinks(p)
	if err != nil {
		return nil, err
	}
	e, ok := f.Paths[rp]
	if !ok {
		return nil, notExist(rp)
	}
	if e.Dir {
		return nil, &fs.PathError{Op: "read", Path: rp, Err: errors.New("is a directory")}
	}
	return e.Data, nil
}

func (f *Fake) Lstat(p string) (os.FileInfo, error) {
	ap, err := f.Abs(p)
	if err != nil {
		return nil, err
	}
	e, ok := f.Paths[ap]
	if !ok {
		return nil, notExist(ap)
	}
	return infoFor(path.Base(ap), e), nil
}

func (f *Fake) ReadDir(p string) ([]os.DirEntry, error) {
	ap, err := f.Abs(p)
	if err != nil {
		return nil, err
	}
	e, ok := f.Paths[ap]
	if !ok {
		return nil, notExist(ap)
	}
	if !e.Dir {
		return nil, &fs.PathError{Op: "readdir", Path: ap, Err: errors.New("not a directory")}
	}
	prefix := strings.TrimSuffix(ap, "/") + "/"
	seen := map[string]bool{}
	var names []string
	for k := range f.Paths {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		rest := k[len(prefix):]
		name := rest
		if i := strings.Index(rest, "/"); i >= 0 {
			name = rest[:i]
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := make([]os.DirEntry, 0, len(names))
	for _, n := range names {
		out = append(out, dirEntry{name: n, entry: f.Paths[prefix+n]})
	}
	return out, nil
}

// EvalSymlinks resolves the path fully, following symlinks in every component,
// mirroring filepath.EvalSymlinks. Missing paths produce a not-exist error.
func (f *Fake) EvalSymlinks(p string) (string, error) {
	cur, err := f.Abs(p)
	if err != nil {
		return "", err
	}
	for i := 0; i < 40; i++ {
		next, changed, err := f.resolveOnce(cur)
		if err != nil {
			return "", err
		}
		if !changed {
			if _, ok := f.Paths[next]; !ok {
				return "", notExist(next)
			}
			return next, nil
		}
		cur = next
	}
	return "", &fs.PathError{Op: "eval", Path: p, Err: errors.New("too many levels of symbolic links")}
}

func (f *Fake) resolveOnce(p string) (string, bool, error) {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := ""
	for i, part := range parts {
		cur = cur + "/" + part
		e, ok := f.Paths[cur]
		if !ok {
			return p, false, nil // a missing component ends resolution
		}
		if e.Symlink != "" {
			target := e.Symlink
			if !strings.HasPrefix(target, "/") {
				target = path.Join(path.Dir(cur), target)
			}
			rest := strings.Join(parts[i+1:], "/")
			np := path.Clean(target)
			if rest != "" {
				np = path.Join(np, rest)
			}
			return np, true, nil
		}
	}
	return path.Clean(p), false, nil
}

func notExist(p string) error {
	return &fs.PathError{Op: "lstat", Path: p, Err: os.ErrNotExist}
}

type dirEntry struct {
	name  string
	entry FakeEntry
}

func (d dirEntry) Name() string               { return d.name }
func (d dirEntry) IsDir() bool                { return d.entry.Dir }
func (d dirEntry) Type() os.FileMode          { return infoFor(d.name, d.entry).Mode().Type() }
func (d dirEntry) Info() (os.FileInfo, error) { return infoFor(d.name, d.entry), nil }

type fileInfo struct {
	name string
	mode os.FileMode
	size int64
	dir  bool
}

func (fi fileInfo) Name() string       { return fi.name }
func (fi fileInfo) Size() int64        { return fi.size }
func (fi fileInfo) Mode() os.FileMode  { return fi.mode }
func (fi fileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (fi fileInfo) IsDir() bool        { return fi.dir }
func (fi fileInfo) Sys() any           { return nil }

func infoFor(name string, e FakeEntry) os.FileInfo {
	mode := e.Mode
	if mode == 0 {
		mode = 0o644
	}
	if e.Dir {
		mode |= os.ModeDir
	}
	if e.Symlink != "" {
		mode |= os.ModeSymlink
	}
	return fileInfo{name: name, mode: mode, size: int64(len(e.Data)), dir: e.Dir}
}
