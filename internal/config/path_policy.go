package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	AllowedSourceRootsEnv      = "CERT_SYNC_ALLOWED_SOURCE_ROOTS"
	AllowedDestinationRootsEnv = "CERT_SYNC_ALLOWED_DESTINATION_ROOTS"
	DefaultSourceRoot          = "/cert_warden_plugin"
	DefaultDestinationRoot     = "/opt/zoraxy/config/conf/certs"
)

// PathPolicy limits source reads and destination writes to operator-approved
// filesystem roots. It is intentionally separate from the web-managed config.
type PathPolicy struct {
	sourceRoots      []string
	destinationRoots []string
}

// PathPolicyFromEnv builds a path policy from OS path-list environment values.
func PathPolicyFromEnv() (*PathPolicy, error) {
	return NewPathPolicy(
		rootsFromEnv(AllowedSourceRootsEnv, DefaultSourceRoot),
		rootsFromEnv(AllowedDestinationRootsEnv, DefaultDestinationRoot),
	)
}

func rootsFromEnv(name, defaultRoot string) []string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return []string{defaultRoot}
	}
	return filepath.SplitList(value)
}

// NewPathPolicy validates and stores source and destination roots.
func NewPathPolicy(sourceRoots, destinationRoots []string) (*PathPolicy, error) {
	sources, err := normalizeRoots(sourceRoots, "source")
	if err != nil {
		return nil, err
	}
	destinations, err := normalizeRoots(destinationRoots, "destination")
	if err != nil {
		return nil, err
	}
	return &PathPolicy{sourceRoots: sources, destinationRoots: destinations}, nil
}

func normalizeRoots(roots []string, label string) ([]string, error) {
	if len(roots) == 0 {
		return nil, fmt.Errorf("at least one allowed %s root is required", label)
	}
	normalized := make([]string, 0, len(roots))
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" || !filepath.IsAbs(root) {
			return nil, fmt.Errorf("allowed %s root must be an absolute path", label)
		}
		clean := filepath.Clean(root)
		if clean != root {
			return nil, fmt.Errorf("allowed %s root must be normalized: %s", label, root)
		}
		normalized = append(normalized, clean)
	}
	return normalized, nil
}

// ValidateSource checks that a source path stays within an allowed source root.
func (p *PathPolicy) ValidateSource(path string, checkExists bool) error {
	_, err := p.ResolveSource(path, checkExists)
	return err
}

// ResolveSource returns a canonical source path contained by the policy.
func (p *PathPolicy) ResolveSource(path string, checkExists bool) (string, error) {
	resolved, err := resolveAllowedPath(path, p.sourceRoots, "source")
	if err != nil {
		return "", err
	}
	if checkExists {
		info, err := os.Stat(resolved)
		if err != nil {
			return "", fmt.Errorf("source path is not accessible: %w", err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("source path must be a file")
		}
	}
	return resolved, nil
}

// ValidateDestination checks that a directory stays within an allowed target root.
func (p *PathPolicy) ValidateDestination(path string, checkExists bool) error {
	_, err := p.ResolveDestination(path, checkExists)
	return err
}

// ResolveDestination returns a canonical destination path contained by the policy.
func (p *PathPolicy) ResolveDestination(path string, checkExists bool) (string, error) {
	resolved, err := resolveAllowedPath(path, p.destinationRoots, "destination")
	if err != nil {
		return "", err
	}
	if checkExists {
		info, err := os.Stat(resolved)
		if err != nil {
			return "", fmt.Errorf("destination path is not accessible: %w", err)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("destination path must be a directory")
		}
	}
	return resolved, nil
}

func resolveAllowedPath(path string, roots []string, label string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("%s path must be absolute and normalized", label)
	}

	resolvedPath, err := resolvePath(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %s path: %w", label, err)
	}
	for _, root := range roots {
		resolvedRoot, err := resolvePath(root)
		if err != nil {
			return "", fmt.Errorf("failed to resolve allowed %s root: %w", label, err)
		}
		if pathWithinRoot(resolvedPath, resolvedRoot) {
			return resolvedPath, nil
		}
	}
	return "", fmt.Errorf("%s path is outside the allowed roots", label)
}

func resolvePath(path string) (string, error) {
	current := filepath.Clean(path)
	missing := make([]string, 0)
	for {
		_, err := os.Lstat(current)
		if err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func pathWithinRoot(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
