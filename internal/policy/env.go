package policy

import (
	"sort"
	"strings"

	"agentbox/internal/agent"
)

// resolveEnv builds the container environment.
//
// Three sources, deliberately kept separate:
//
//   - the agent's BaseEnv, which is sandbox wiring (HOME, XDG_*, PATH) and
//     always applies;
//   - PassthroughEnv names, copied from the host so terminals and locales work;
//   - --env names, which may carry credentials and are therefore gated on the
//     agent's allowlist.
//
// Nothing else crosses. --unsetenv-all is emitted separately by the argv
// builder, so a name absent from this list is absent from the container rather
// than inherited from podman's defaults.
func resolveEnv(def agent.Definition, requested []string, lookup func(string) (string, bool)) ([]EnvPair, []Refusal) {
	var refusals []Refusal

	allowed := make(map[string]bool, len(def.EnvAllowlist))
	for _, n := range def.EnvAllowlist {
		allowed[n] = true
	}

	index := map[string]int{}
	var out []EnvPair
	add := func(name, value string) {
		if i, ok := index[name]; ok {
			out[i].Value = value
			return
		}
		index[name] = len(out)
		out = append(out, EnvPair{Name: name, Value: value})
	}

	for _, name := range sortedKeys(def.BaseEnv) {
		add(name, def.BaseEnv[name])
	}

	for _, name := range def.PassthroughEnv {
		if v, ok := lookup(name); ok {
			add(name, v)
		}
	}

	for _, name := range requested {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !allowed[name] {
			refusals = append(refusals, refusal(RefusalEnv, name,
				"not on this agent's environment allowlist; credentials never cross unless the agent declares the name"))
			continue
		}
		v, ok := lookup(name)
		if !ok {
			refusals = append(refusals, warn(RefusalEnv, name,
				"requested but not set on the host; not passed"))
			continue
		}
		add(name, v)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, refusals
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
