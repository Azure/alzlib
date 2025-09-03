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
	"regexp"
	"slices"
	"strings"

	"github.com/Azure/alzlib/internal/processor"
	"github.com/Azure/alzlib/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
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
type FSWriter struct {
	opts FSWriterOptions
}

// FSWriterOptions defines options for the filesystem writer.
type FSWriterOptions struct {
	// number of times to escape ARM expressions in policy definitions
	ArmEscapePolicyDefinitions uint
	// number of times to escape ARM expressions in policy set definitions
	ArmEscapePolicySetDefinitions uint
	// number of times to escape ARM expressions in role definitions
	ArmEscapeRoleDefinitions uint
	// number of times to escape ARM expressions in policy assignments
	ArmEscapePolicyAssignments uint
	// options for customization of policy set definitions
	PolicySetOptions FSWriterPolicySetOptions
}

// FSWriterPolicySetOptions defines options for the policy set definitions.
type FSWriterPolicySetOptions struct {
	// if true, replaces custom policy definition references in policy set definitions
	CustomPolicyDefinitionReferencesUpdate bool
	// regular expression to match custom policy definition references
	CustomPolicyDefinitionReferenceRegExp *regexp.Regexp
	// value to replace custom policy definition references
	CustomPolicyDefinitionReferenceReplaceValue string
}

// NewFSWriter creates a new filesystem writer with optional configuration.
func NewFSWriter(opt FSWriterOptions) *FSWriter {
	w := &FSWriter{
		opts: opt,
	}

	return w
}

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

	slices.Sort(rootNames)

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
	slices.SortFunc(children, func(a, b *HierarchyManagementGroup) int {
		return strings.Compare(a.Name(), b.Name())
	})

	for _, child := range children {
		if err := w.writeMgmtGroupRecursive(ctx, h, child.Name(), dir); err != nil {
			return err
		}
	}

	return nil
}

func (w *FSWriter) writePolicyAssignments(ctx context.Context, dir string, mg *HierarchyManagementGroup) error {
	m := mg.PolicyAssignmentMap()

	for _, pa := range m {
		// we don't need to safely dereference the name because the assets package does this for us
		if err := writeAsset(
			ctx,
			*pa.Name,
			dir,
			fileSuffixPolicyAssignment,
			pa,
			w.opts.ArmEscapePolicyAssignments,
		); err != nil {
			return err
		}
	}

	return nil
}

func (w *FSWriter) writePolicyDefinitions(ctx context.Context, dir string, mg *HierarchyManagementGroup) error {
	m := mg.PolicyDefinitionsMap()

	for _, pa := range m {
		// we don't need to safely dereference the name because the assets package does this for us
		if err := writeAsset(
			ctx,
			*pa.Name,
			dir,
			string(fileSuffixPolicyDefinition),
			pa,
			w.opts.ArmEscapePolicyDefinitions,
		); err != nil {
			return err
		}
	}

	return nil
}

func (w *FSWriter) writePolicySetDefinitions(ctx context.Context, dir string, mg *HierarchyManagementGroup) error {
	m := mg.PolicySetDefinitionsMap()
	if len(m) == 0 {
		return nil
	}

	for _, psd := range m {
		if w.opts.PolicySetOptions.CustomPolicyDefinitionReferencesUpdate {
			updatePolicyDefinitionReferences(
				psd.Properties.PolicyDefinitions,
				w.opts.PolicySetOptions.CustomPolicyDefinitionReferenceRegExp,
				w.opts.PolicySetOptions.CustomPolicyDefinitionReferenceReplaceValue,
			)
		}

		// we don't need to safely dereference the name because the assets package does this for us
		if err := writeAsset(
			ctx,
			*psd.Name,
			dir,
			string(fileSuffixPolicySetDefinition),
			psd, w.opts.ArmEscapePolicySetDefinitions,
		); err != nil {
			return err
		}
	}

	return nil
}

func (w *FSWriter) writeRoleDefinitions(ctx context.Context, dir string, mg *HierarchyManagementGroup) error {
	m := mg.RoleDefinitionsMap()

	for _, rd := range m {
		// we don't need to safely dereference the name because the assets package does this for us
		if err := writeAsset(
			ctx,
			*rd.Name,
			dir,
			fileSuffixRoleDefinition,
			rd,
			w.opts.ArmEscapeRoleDefinitions,
		); err != nil {
			return err
		}
	}

	return nil
}

// Helpers

func updatePolicyDefinitionReferences(pdrefs []*armpolicy.DefinitionReference, re *regexp.Regexp, replace string) {
	for _, pdref := range pdrefs {
		if pdref.PolicyDefinitionID == nil {
			continue
		}

		oldPolicyDefID := *pdref.PolicyDefinitionID
		pdref.PolicyDefinitionID = to.Ptr(re.ReplaceAllString(oldPolicyDefID, replace))
	}
}

func writeAsset[T any](ctx context.Context, name, dir, suffix string, asset T, escapeIterations uint) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}

	file := filepath.Join(dir, sanitizeFilename(name)+suffix)
	if escapeIterations > 0 {
		if err := writeJSONFileEscaped(ctx, file, asset, escapeIterations); err != nil {
			return fmt.Errorf("writing asset %q: %w", name, err)
		}

		return nil
	}

	if err := writeJSONFile(file, asset); err != nil {
		return fmt.Errorf("writing asset %q: %w", name, err)
	}

	return nil
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
		panic("context is nil, use context.Background() or context.TODO()")
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

// writeJSONFileMaybeEscaped writes v as JSON to finalPath. When the writer is configured
// with escapeARM=true, it first materializes v into generic JSON types (map[string]any/[]any),
// applies addArmFunctionEscaping to escape ARM function expressions, and then writes the result.
func writeJSONFileEscaped(ctx context.Context, finalPath string, v any, iterations uint) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}

	// Marshal to JSON then unmarshal into interface{} to obtain maps/slices for traversal.
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal for escaping: %w", err)
	}

	var m any
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("unmarshal for escaping: %w", err)
	}

	for i := range iterations {
		if err := addArmFunctionEscaping(m); err != nil {
			return fmt.Errorf("escape ARM functions (iteration %d): %w", i, err)
		}
	}

	return writeJSONFile(finalPath, m)
}

func addArmFunctionEscaping(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			switch vv := val.(type) {
			case string:
				// If the string starts with [ (open bracket),
				// add an extra [ to escape ARM template function evaluation.
				if strings.HasPrefix(vv, "[") {
					t[k] = "[[" + vv[1:]
					continue
				}
			case map[string]any, []any:
				if err := addArmFunctionEscaping(vv); err != nil {
					return err
				}
			}
		}
	case []any:
		for i, elem := range t {
			switch e := elem.(type) {
			case string:
				if strings.HasPrefix(e, "[") {
					t[i] = "[[" + e[1:]
					continue
				}
			case map[string]any, []any:
				if err := addArmFunctionEscaping(e); err != nil {
					return err
				}
			}
		}
	default:
		// other scalar types (bool, float64, nil, json.Number, etc.) are ignored
	}

	return nil
}
