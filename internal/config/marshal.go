package config

import (
	"bytes"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Marshal encodes c as authdiff.yaml that Load reads back to an equal
// config: empty and zero fields are left out, durations are written as
// "10s", and a profile's name is its map key. Values are written as they
// are, so a token placeholder such as ${env:ALICE_TOKEN} stays a
// placeholder; a real token would be written in clear text.
func Marshal(c *Config) ([]byte, error) {
	if c == nil {
		return nil, errors.New("config: marshal nil config")
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return buf.Bytes(), nil
}

// Clone returns a deep copy of c (nil for nil): no map, slice or nested
// body value is shared with c.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	out := *c
	out.Scope.AllowHosts = cloneStrings(c.Scope.AllowHosts)
	if c.Profiles != nil {
		out.Profiles = make(map[string]Profile, len(c.Profiles))
		for k, p := range c.Profiles {
			if p.Owns != nil {
				owns := make(map[string][]string, len(p.Owns))
				for param, ids := range p.Owns {
					owns[param] = cloneStrings(ids)
				}
				p.Owns = owns
			}
			p.Identifiers = cloneStrings(p.Identifiers)
			out.Profiles[k] = p
		}
	}
	if c.Harvest != nil {
		out.Harvest = make([]HarvestRule, len(c.Harvest))
		for i, h := range c.Harvest {
			if h.Extract != nil {
				ex := make(map[string]string, len(h.Extract))
				for k, v := range h.Extract {
					ex[k] = v
				}
				h.Extract = ex
			}
			out.Harvest[i] = h
		}
	}
	if c.Matrix != nil {
		out.Matrix = make(map[string]MatrixRule, len(c.Matrix))
		for k, m := range c.Matrix {
			out.Matrix[k] = MatrixRule{Allow: cloneStrings(m.Allow)}
		}
	}
	out.Compare.IgnoreFields = cloneStrings(c.Compare.IgnoreFields)
	out.Output.Formats = cloneStrings(c.Output.Formats)
	out.Filter = Filter{Include: cloneStrings(c.Filter.Include), Exclude: cloneStrings(c.Filter.Exclude),
		Tags: cloneStrings(c.Filter.Tags)}
	if c.Bodies != nil {
		out.Bodies, _ = cloneValue(c.Bodies).(map[string]any)
	}
	out.Rules = RulesCfg{Dirs: cloneStrings(c.Rules.Dirs), Disable: cloneStrings(c.Rules.Disable)}
	return &out
}

// cloneStrings copies s, keeping nil as nil and empty as empty.
func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	return append(make([]string, 0, len(s)), s...)
}

// cloneValue deep-copies the maps and slices of a decoded YAML value.
func cloneValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = cloneValue(x)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, x := range t {
			s[i] = cloneValue(x)
		}
		return s
	}
	return v
}
