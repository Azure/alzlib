// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Azure/alzlib/assets"
	"github.com/Azure/alzlib/internal/processor"
)

// HierarchyWriter writes a Hierarchy to a target location.
// Implementations should mirror the management group hierarchy on the target.
type HierarchyWriter interface {
	// Write exports the hierarchy to outDir. Each management group becomes a directory
	// (nested according to parent/child), and each asset (policy assignment/definition,
	// policy set definition, role definition) is written as a separate JSON file named
	// using the asset JSON .name plus a type-specific suffix.
	Write(ctx context.Context, h *Hierarchy, outDir string) error
}

// FSWriter writes a Hierarchy to the local filesystem.
type FSWriter struct{}

// NewFSWriter creates a new filesystem writer.
func NewFSWriter() *FSWriter { return &FSWriter{} }

const (
	fileSuffixPolicyAssignment    = "." + processor.PolicyAssignmentFileType + ".json"
	fileSuffixPolicyDefinition    = "." + processor.PolicyDefinitionFileType + ".json"
	fileSuffixPolicySetDefinition = "." + processor.PolicySetDefinitionFileType + ".json"
	fileSuffixRoleDefinition      = "." + processor.RoleDefinitionFileType + ".json"
)

const (
	dirPerm          = 0o755
	filePerm         = 0o644
	controlCharLimit = 0x20
)

// Write implements HierarchyWriter.
func (w *FSWriter) Write(ctx context.Context, h *Hierarchy, outDir string) error {
	if h == nil {
		return errors.New("fswriter.write: hierarchy is nil")
	}

	if strings.TrimSpace(outDir) == "" {
		return errors.New("fswriter.write: outDir is empty")
	}

	if err := os.MkdirAll(outDir, dirPerm); err != nil {
		return fmt.Errorf("fswriter.write: creating outDir: %w", err)
	}

	// Identify roots (Parent() == nil indicates internal parent is nil; external parents are still roots for file layout).
	rootNames := make([]string, 0)

	for _, name := range h.ManagementGroupNames() {
		mg := h.ManagementGroup(name)
		if mg == nil {
			continue
		}

		if mg.Parent() == nil {
			rootNames = append(rootNames, mg.Name())
		}
	}

	sort.Strings(rootNames)

	for _, root := range rootNames {
		if err := w.writeMgmtGroupRecursive(ctx, h, root, outDir); err != nil {
			return err
		}
	}

	return nil
}

func (w *FSWriter) writeMgmtGroupRecursive(ctx context.Context, h *Hierarchy, mgName, base string) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}

	mg := h.ManagementGroup(mgName)
	if mg == nil {
		return fmt.Errorf("fswriter.writeMgmtGroupRecursive: management group %q not found", mgName)
	}

	// Directory path for this MG
	dir := filepath.Join(base, sanitizeFilename(mg.Name()))
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("fswriter.writeMgmtGroupRecursive: creating dir %q: %w", dir, err)
	}

	// Write assets for this MG
	if err := w.writePolicyAssignments(ctx, dir, mg); err != nil {
		return err
	}

	if err := w.writePolicyDefinitions(ctx, dir, mg); err != nil {
		return err
	}

	if err := w.writePolicySetDefinitions(ctx, dir, mg); err != nil {
		return err
	}

	if err := w.writeRoleDefinitions(ctx, dir, mg); err != nil {
		return err
	}

	// Recurse into children: stable order by child name
	children := mg.Children()
	sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })

	for _, child := range children {
		if err := w.writeMgmtGroupRecursive(ctx, h, child.Name(), dir); err != nil {
			return err
		}
	}

	return nil
}

func (w *FSWriter) writePolicyAssignments(ctx context.Context, dir string, mg *HierarchyManagementGroup) error {
	m := mg.PolicyAssignmentMap()
	if len(m) == 0 {
		return nil
	}

	list := make([]*assets.PolicyAssignment, 0, len(m))
	for _, v := range m {
		list = append(list, v)
	}

	sort.Slice(list, func(i, j int) bool { return derefString(list[i].Name, "") < derefString(list[j].Name, "") })

	for _, pa := range list {
		if err := ctxErr(ctx); err != nil {
			return err
		}

		assetName := derefString(pa.Name, "")

		file := filepath.Join(dir, sanitizeFilename(assetName)+fileSuffixPolicyAssignment)
		if err := writeJSONFile(file, pa); err != nil {
			return fmt.Errorf("writing policy assignment %q: %w", assetName, err)
		}
	}

	return nil
}

func (w *FSWriter) writePolicyDefinitions(ctx context.Context, dir string, mg *HierarchyManagementGroup) error {
	m := mg.PolicyDefinitionsMap()
	if len(m) == 0 {
		return nil
	}

	list := make([]*assets.PolicyDefinition, 0, len(m))
	for _, v := range m {
		list = append(list, v)
	}

	sort.Slice(list, func(i, j int) bool { return derefString(list[i].Name, "") < derefString(list[j].Name, "") })

	for _, pd := range list {
		if err := ctxErr(ctx); err != nil {
			return err
		}

		assetName := derefString(pd.Name, "")

		file := filepath.Join(dir, sanitizeFilename(assetName)+fileSuffixPolicyDefinition)
		if err := writeJSONFile(file, pd); err != nil {
			return fmt.Errorf("writing policy definition %q: %w", assetName, err)
		}
	}

	return nil
}

func (w *FSWriter) writePolicySetDefinitions(ctx context.Context, dir string, mg *HierarchyManagementGroup) error {
	m := mg.PolicySetDefinitionsMap()
	if len(m) == 0 {
		return nil
	}

	list := make([]*assets.PolicySetDefinition, 0, len(m))
	for _, v := range m {
		list = append(list, v)
	}

	sort.Slice(list, func(i, j int) bool { return derefString(list[i].Name, "") < derefString(list[j].Name, "") })

	for _, psd := range list {
		if err := ctxErr(ctx); err != nil {
			return err
		}

		assetName := derefString(psd.Name, "")

		file := filepath.Join(dir, sanitizeFilename(assetName)+fileSuffixPolicySetDefinition)
		if err := writeJSONFile(file, psd); err != nil {
			return fmt.Errorf("writing policy set definition %q: %w", assetName, err)
		}
	}

	return nil
}

func (w *FSWriter) writeRoleDefinitions(ctx context.Context, dir string, mg *HierarchyManagementGroup) error {
	m := mg.RoleDefinitionsMap()
	if len(m) == 0 {
		return nil
	}

	list := make([]*assets.RoleDefinition, 0, len(m))
	for _, v := range m {
		list = append(list, v)
	}

	sort.Slice(list, func(i, j int) bool { return derefString(list[i].Name, "") < derefString(list[j].Name, "") })

	for _, rd := range list {
		if err := ctxErr(ctx); err != nil {
			return err
		}

		assetName := derefString(rd.Name, "")

		file := filepath.Join(dir, sanitizeFilename(assetName)+fileSuffixRoleDefinition)
		if err := writeJSONFile(file, rd); err != nil {
			return fmt.Errorf("writing role definition %q: %w", assetName, err)
		}
	}

	return nil
}

// Helpers

// Note: sorting is now done on slices built from map values; helpers removed.

func derefString(p *string, fallback string) string {
	if p == nil || *p == "" {
		return fallback
	}

	return *p
}

func sanitizeFilename(s string) string {
	if s == "" {
		return "unnamed"
	}
	// Replace path separators and common problematic characters; trim spaces.
	replacer := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_",
	)
	s = replacer.Replace(s)
	s = strings.Map(func(r rune) rune {
		if r < controlCharLimit {
			return '_' // control chars
		}

		return r
	}, s)

	s = strings.TrimSpace(s)
	if s == "" {
		return "unnamed"
	}

	return s
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func writeJSONFile(finalPath string, v any) error {
	dir := filepath.Dir(finalPath)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create dir for %q: %w", finalPath, err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*.json")
	if err != nil {
		return fmt.Errorf("create temp file for %q: %w", finalPath, err)
	}

	tmpName := tmp.Name()
	// Ensure cleanup on failure
	defer func() { _ = os.Remove(tmpName) }()

	enc := json.NewEncoder(tmp)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(v); err != nil { // adds a trailing newline which is fine
		_ = tmp.Close()
		return fmt.Errorf("encode json for %q: %w", finalPath, err)
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp for %q: %w", finalPath, err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp for %q: %w", finalPath, err)
	}

	if err := os.Rename(tmpName, finalPath); err != nil {
		return fmt.Errorf("rename temp to final for %q: %w", finalPath, err)
	}

	if err := os.Chmod(finalPath, filePerm); err != nil {
		return fmt.Errorf("chmod final for %q: %w", finalPath, err)
	}

	return nil
}
