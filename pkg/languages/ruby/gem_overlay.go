/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package ruby

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/omnibump/pkg/languages"
	"golang.org/x/mod/semver"
)

// gemNameRe validates gem names according to RubyGems conventions.
// Matches names like "rack", "net-http", "activerecord", "nokogiri" but rejects
// names starting with "-" (injection prevention) or containing invalid characters.
var gemNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// gemspecFileRe parses gemspec filenames into name and version components.
// Gemspec files follow the pattern: name-version.gemspec (e.g. "rack-3.1.9.gemspec").
// The version is the last hyphen-separated segment that starts with a digit.
var gemspecFileRe = regexp.MustCompile(`^(.+)-(\d[^-]*)\.gemspec$`)

// gemSpecifier represents a gem name + version pair for overlay installation.
type gemSpecifier struct {
	Name    string
	Version string
}

// updateGemDir installs gems into an existing gem directory, overlaying patched
// versions on top of the bundled ones. This is the Ruby equivalent of Python's
// venv mode — used for CVE remediation when a transitive dependency needs
// patching without rebuilding the entire bundle.
func updateGemDir(ctx context.Context, cfg *languages.UpdateConfig, gemDirPath string) error {
	log := clog.FromContext(ctx)

	// Ensure gem dir path is absolute
	absGemDir, err := filepath.Abs(gemDirPath)
	if err != nil {
		return fmt.Errorf("invalid gem-dir path: %w", err)
	}

	// Verify gem dir exists
	if _, err := os.Stat(absGemDir); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrGemDirNotFound, absGemDir, err)
	}

	log.Infof("Using Ruby gem directory at: %s", absGemDir)

	// Validate and parse gem specs
	specs, err := parseAndValidateGemSpecs(cfg.Dependencies)
	if err != nil {
		return err
	}

	if len(specs) == 0 {
		log.Infof("No gems to update")
		return nil
	}

	// Snapshot installed versions from specifications/ directory
	installed, err := listInstalledGems(absGemDir)
	if err != nil {
		// Non-fatal: specifications/ dir may not exist yet
		log.Warnf("Could not list installed gems: %v", err)
		installed = make(map[string]string)
	}

	// Check current versions and reject downgrades
	for _, spec := range specs {
		current := installed[spec.Name]

		if current != "" {
			if isGemVersionLower(spec.Version, current) {
				return fmt.Errorf("%w: %s from %s to %s", ErrGemDirDowngrade, spec.Name, current, spec.Version)
			}

			if current == spec.Version {
				log.Infof("%s: already at %s", spec.Name, current)
			} else {
				log.Infof("%s: %s -> %s", spec.Name, current, spec.Version)
			}
		} else {
			log.Infof("%s: (new) -> %s", spec.Name, spec.Version)
		}
	}

	if cfg.DryRun {
		log.Infof("[dry-run] would install: %v", specs)
		return nil
	}

	// Install each gem one at a time
	for _, spec := range specs {
		if err := installGem(ctx, absGemDir, spec); err != nil {
			return fmt.Errorf("%w: %s@%s: %w", ErrGemInstallFailed, spec.Name, spec.Version, err)
		}
		log.Infof("Installed %s@%s", spec.Name, spec.Version)
	}

	log.Infof("Updated gems in %s", absGemDir)
	return nil
}

// validateGemDir verifies that all expected gems are installed at the expected
// versions by scanning the specifications/ directory.
func validateGemDir(ctx context.Context, cfg *languages.UpdateConfig, gemDirPath string) error {
	log := clog.FromContext(ctx)

	absGemDir, err := filepath.Abs(gemDirPath)
	if err != nil {
		return fmt.Errorf("invalid gem-dir path: %w", err)
	}

	if _, err := os.Stat(absGemDir); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrGemDirNotFound, absGemDir, err)
	}

	installed, err := listInstalledGems(absGemDir)
	if err != nil {
		return fmt.Errorf("failed to list installed gems: %w", err)
	}

	for _, dep := range cfg.Dependencies {
		current := installed[dep.Name]

		if current == "" {
			return fmt.Errorf("%w: %s not found in gem directory", ErrPackageNotFound, dep.Name)
		}

		if current != dep.Version {
			log.Warnf("validation: %s expected %s but found %s", dep.Name, dep.Version, current)
			return fmt.Errorf("%w: %s expected %s, got %s", ErrValidationFailed, dep.Name, dep.Version, current)
		}

		log.Debugf("validation ok: %s == %s", dep.Name, current)
	}

	return nil
}

// parseAndValidateGemSpecs validates that all dependencies have valid gem names
// and versions. Rejects names that could be interpreted as command-line options.
func parseAndValidateGemSpecs(deps []languages.Dependency) ([]gemSpecifier, error) {
	specs := make([]gemSpecifier, 0, len(deps))

	for _, dep := range deps {
		// Reject names starting with '-' to prevent option injection
		if strings.HasPrefix(dep.Name, "-") {
			return nil, fmt.Errorf("%w: %q (cannot start with '-')", ErrGemDirInvalidGemName, dep.Name)
		}

		// Validate gem name format
		if !gemNameRe.MatchString(dep.Name) {
			return nil, fmt.Errorf("%w: %q (must match gem naming conventions)", ErrGemDirInvalidGemName, dep.Name)
		}

		if dep.Version == "" {
			return nil, fmt.Errorf("%w: %s", ErrGemDirEmptyVersion, dep.Name)
		}

		// Reject versions starting with '-' (injection prevention)
		if strings.HasPrefix(dep.Version, "-") {
			return nil, fmt.Errorf("%w: %q for gem %s", ErrGemDirInvalidVersionFormat, dep.Version, dep.Name)
		}

		specs = append(specs, gemSpecifier{
			Name:    dep.Name,
			Version: dep.Version,
		})
	}

	return specs, nil
}

// installGem runs `gem install` to install a single gem into the specified directory.
func installGem(ctx context.Context, gemDir string, spec gemSpecifier) error {
	//nolint:gosec // args are constructed from validated gem specs (gemNameRe, version checks)
	cmd := exec.CommandContext(ctx, "gem", "install", spec.Name,
		"--install-dir", gemDir,
		"--no-document",
		"--version", spec.Version,
		"--force",
		"--no-user-install",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gem install failed: %s: %w", stderr.String(), err)
	}

	return nil
}

// listInstalledGems scans <gemDir>/specifications/*.gemspec and returns a map
// of gem name → version. This avoids shelling out to `gem list`.
// When multiple versions of the same gem are installed, the highest version wins.
func listInstalledGems(gemDir string) (map[string]string, error) {
	specsDir := filepath.Join(gemDir, "specifications")

	entries, err := os.ReadDir(specsDir)
	if err != nil {
		return nil, fmt.Errorf("reading specifications directory: %w", err)
	}

	m := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		matches := gemspecFileRe.FindStringSubmatch(entry.Name())
		if matches == nil {
			continue
		}

		name := matches[1]
		version := matches[2]

		// Keep the highest version if multiple are installed
		if existing, ok := m[name]; ok {
			if !isGemVersionLower(version, existing) {
				m[name] = version
			}
		} else {
			m[name] = version
		}
	}

	return m, nil
}

// isGemVersionLower returns true if v1 < v2 according to semver ordering.
// Falls back to lexicographic comparison if either version is not valid semver.
func isGemVersionLower(v1, v2 string) bool {
	// golang.org/x/mod/semver requires a "v" prefix
	sv1 := "v" + v1
	sv2 := "v" + v2

	if semver.IsValid(sv1) && semver.IsValid(sv2) {
		return semver.Compare(sv1, sv2) < 0
	}

	// Fallback to lexicographic comparison
	return v1 < v2
}
