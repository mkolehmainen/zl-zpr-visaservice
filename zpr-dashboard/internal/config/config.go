// Package config loads the dashboard's settings from a TOML file and exports
// them as environment variables. Nothing has to carry a config struct around:
// callers read os.Getenv (see dataplane.NewDefault) and values already present
// in the real environment always win over the file.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Map config on the config.toml to env variables (accessible everywere)
const (
	EnvBaseURL    = "ZPR_BASE_URL"
	EnvTimeout    = "ZPR_TIMEOUT"
	EnvAPIKey     = "ZPR_API_KEY"
	EnvCAFile     = "ZPR_CA_FILE"
	EnvKeyFile    = "ZPR_KEY_FILE"
	EnvShowStatic = "ZPR_SHOW_STATIC"
)

// Structure of config.toml file
type file struct {
	Dataplane struct {
		BaseURL string `toml:"base_url"`
		Timeout string `toml:"timeout"`
		APIKey  string `toml:"api_key"`
	} `toml:"dataplane"`

	Files struct {
		CA  string `toml:"ca"`
		Key string `toml:"key"`
	} `toml:"files"`

	UI struct {
		ShowStatic *bool `toml:"show_static"`
	} `toml:"ui"`
}

// Load config.toml file
func Load() error {
	path := "config.toml"

	var cfg file
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return fmt.Errorf("Read config %s: %w", path, err)
	}

	// Throw on invalid keys
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			keys = append(keys, key.String())
		}
		return fmt.Errorf("Unknown key(s) in %s: %s", path, strings.Join(keys, ", "))
	}

	// Ensure timeout is a number
	if cfg.Dataplane.Timeout != "" {
		if _, err := time.ParseDuration(cfg.Dataplane.Timeout); err != nil {
			return fmt.Errorf("Parse dataplane.timeout in %s: %w", path, err)
		}
	}

	dir := filepath.Dir(path)

	setenv(EnvBaseURL, cfg.Dataplane.BaseURL)
	setenv(EnvTimeout, cfg.Dataplane.Timeout)
	setenv(EnvAPIKey, cfg.Dataplane.APIKey)
	setenv(EnvCAFile, resolve(dir, cfg.Files.CA))
	setenv(EnvKeyFile, resolve(dir, cfg.Files.Key))

	if cfg.UI.ShowStatic != nil {
		setenv(EnvShowStatic, strconv.FormatBool(*cfg.UI.ShowStatic))
	}

	// Enable/Disable static components
	if raw := os.Getenv(EnvShowStatic); raw != "" {
		if _, err := strconv.ParseBool(raw); err != nil {
			return fmt.Errorf("Parse %s: %q is not a boolean", EnvShowStatic, raw)
		}
	}

	return nil
}

func ShowStatic() bool {
	show, err := strconv.ParseBool(os.Getenv(EnvShowStatic))
	if err != nil {
		return true
	}

	return show
}

// Set the env variable, skip if it already exists
func setenv(key, value string) {
	if value == "" {
		return
	}

	if _, ok := os.LookupEnv(key); ok {
		return
	}

	os.Setenv(key, value)
}

// Resolve config.toml file path
func resolve(dir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}

	return filepath.Join(dir, path)
}
