// Package config provides YAML-based custom rule loading for AirLock.
// Operators can extend AirLock's detection capabilities at runtime by
// placing a rules.yaml file in the config/ directory. Rules are loaded
// once at startup and appended to the appropriate security layer.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Rule represents a single custom detection rule defined by an operator.
type Rule struct {
	ID       string   `yaml:"id"`
	Name     string   `yaml:"name"`
	Layer    string   `yaml:"layer"`
	Type     string   `yaml:"type"`
	Patterns []string `yaml:"patterns"`
	Action   string   `yaml:"action"`
	Severity string   `yaml:"severity"`
}

// RulesConfig is the top-level structure of the rules.yaml file.
type RulesConfig struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// LoadRules reads and unmarshals the YAML rules file at the given path.
// Returns the parsed config or an error if the file cannot be read or parsed.
// The caller should treat a missing file as non-fatal (log a warning and
// continue with built-in defaults).
func LoadRules(path string) (*RulesConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: cannot read rules file %q: %w", path, err)
	}

	var cfg RulesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: cannot parse rules file %q: %w", path, err)
	}

	return &cfg, nil
}
