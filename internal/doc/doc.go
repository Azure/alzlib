// Copyright (c) Microsoft Corporation 2025. All rights reserved.
// SPDX-License-Identifier: MIT

// Package doc provides functions to generate documentation for alzlib libraries in Markdown format.
package doc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Azure/alzlib"
	"github.com/nao1215/markdown"
)

var (
	ErrReadmeGenerationFailed = fmt.Errorf("failed to generate README")
)

// AlzlibReadmeMd generates a Markdown formatted README for the given alzlib libraries.
func AlzlibReadmeMd(ctx context.Context, w io.Writer, libs ...alzlib.LibraryReference) error {
	az := alzlib.NewAlzLib(nil)
	if err := az.Init(ctx, libs...); err != nil {
		return fmt.Errorf("doc.AlzlibReadmeMd: failed to initialize alzlib: %w", err)
	}

	metadataS := az.Metadata()
	metad := metadataS[len(metadataS)-1]

	md := markdown.NewMarkdown(w)

	md = alzlibReadmeMdTitle(md, metad)
	md = alzlibReadmeMdDependencies(md, metad.Dependencies())
	md = alzlibReadmeMdUsage(md, metad.Path())
	md = alzlibReadmeMdArchitectures(md, az)
	md = alzlibReadmeMdArchetypes(md, az)
	md = alzlibReadmeMdPolicyDefaultValues(md, az)
	md = md.HorizontalRule()
	md = alzlibReadmeMdContents(md, az)

	err := md.Build()
	if err != nil {
		return errors.Join(ErrReadmeGenerationFailed, err)
	}

	return nil
}

func alzlibReadmeMdTitle(md *markdown.Markdown, metad *alzlib.Metadata) *markdown.Markdown {
	name := metad.Name()
	if name == "" {
		name = "No name in metadata"
	}

	displayName := metad.DisplayName()
	if displayName == "" {
		displayName = "No display name in metadata"
	}

	description := metad.Description()
	if description == "" {
		description = "No description in metadata"
	}

	return md.H1f("%s (%s)", name, displayName).LF().
		PlainText(description).LF()
}

func alzlibReadmeMdDependencies(
	md *markdown.Markdown,
	deps alzlib.LibraryReferences,
) *markdown.Markdown {
	if len(deps) == 0 {
		return md
	}

	md = md.H2("Dependencies").LF()
	for _, dep := range deps {
		md = md.BulletList(dep.String())
	}

	return md.LF()
}

func alzlibReadmeMdUsage(md *markdown.Markdown, path string) *markdown.Markdown {
	return md.H2("Usage").LF().
		CodeBlocks(markdown.SyntaxHighlight("terraform"), fmt.Sprintf(`provider "alz" {
  library_references = [
    {
      path = "%s"
      ref  = "0000.00.0" # Replace with the desired version
    }
  ]
}`, path)).LF()
}

func alzlibReadmeMdArchitectures(md *markdown.Markdown, az *alzlib.AlzLib) *markdown.Markdown {
	archs := az.Architectures()
	if len(archs) == 0 {
		return md
	}

	md = md.H2("Architectures").LF().
		PlainText("The following architectures are available in this library, please note that the diagrams denote " +
			"the management group display name and, in brackets, the associated archetypes:").
		LF()
	for _, a := range archs {
		md = alzlibReadmeMdArchitecture(md, az.Architecture(a))
	}

	return md
}

func alzlibReadmeMdArchetypes(md *markdown.Markdown, az *alzlib.AlzLib) *markdown.Markdown {
	archetypes := az.Archetypes()
	if len(archetypes) == 0 {
		return md
	}

	md = md.H2("Archetypes").LF()

	for _, a := range archetypes {
		archetype := az.Archetype(a)
		pds := archetype.PolicyDefinitions.ToSlice()
		slices.Sort(pds)

		psds := archetype.PolicySetDefinitions.ToSlice()
		slices.Sort(psds)

		rds := archetype.RoleDefinitions.ToSlice()
		slices.Sort(rds)

		pas := archetype.PolicyAssignments.ToSlice()
		slices.Sort(pas)

		if len(pds) > 0 || len(psds) > 0 || len(pas) > 0 || len(rds) > 0 {
			md = md.H3("archetype `" + archetype.Name() + "`").LF()
			if len(pds) > 0 {
				md.H4(a+" policy definitions").LF().
					Details(fmt.Sprintf("%d policy definitions", archetype.PolicyDefinitions.Cardinality()),
						"\n- "+strings.Join(pds, "\n- ")).
					LF()
			}

			if len(psds) > 0 {
				md = md.H4(a+" policy set definitions").LF().
					Details(fmt.Sprintf("%d policy set definitions", archetype.PolicySetDefinitions.Cardinality()),
						"\n- "+strings.Join(psds, "\n- ")).
					LF()
			}

			if len(pas) > 0 {
				md = md.H4(a+" policy assignments").LF().
					Details(fmt.Sprintf("%d policy assignments", archetype.PolicyAssignments.Cardinality()),
						"\n- "+strings.Join(pas, "\n- ")).
					LF()
			}

			if len(rds) > 0 {
				md = md.H4(a+" role definitions").LF().
					Details(fmt.Sprintf("%d role definitions", archetype.RoleDefinitions.Cardinality()),
						"\n- "+strings.Join(rds, "\n- ")).
					LF()
			}
		}
	}

	return md
}

func alzlibReadmeMdContents(md *markdown.Markdown, az *alzlib.AlzLib) *markdown.Markdown {
	md = md.H2("Contents").LF()
	if len(az.PolicyDefinitions()) > 0 {
		md = md.H3("all policy definitions").LF().
			Details(fmt.Sprintf("%d policy definitions", len(az.PolicyDefinitions())),
				"\n- "+strings.Join(az.PolicyDefinitions(), "\n- ")).
			LF()
	}

	if len(az.PolicySetDefinitions()) > 0 {
		md = md.H3("all policy set definitions").LF().
			Details(fmt.Sprintf("%d policy set definitions", len(az.PolicySetDefinitions())),
				"\n- "+strings.Join(az.PolicySetDefinitions(), "\n- ")).
			LF()
	}

	if len(az.PolicyAssignments()) > 0 {
		md = md.H3("all policy assignments").LF().
			Details(fmt.Sprintf("%d policy assignments", len(az.PolicyAssignments())),
				"\n- "+strings.Join(az.PolicyAssignments(), "\n- ")).
			LF()
	}

	if len(az.RoleDefinitions()) > 0 {
		md = md.H3("all role definitions").LF().
			Details(fmt.Sprintf("%d role definitions", len(az.RoleDefinitions())),
				"\n- "+strings.Join(az.RoleDefinitions(), "\n- ")).
			LF()
	}

	return md
}

func alzlibReadmeMdArchitecture(md *markdown.Markdown, a *alzlib.Architecture) *markdown.Markdown {
	return md.H3("architecture `"+a.Name()+"`").LF().
		Note("This hierarchy will be deployed as a child of the user-supplied root management group.").
		LF().
		CodeBlocks("mermaid", mermaidFromArchitecture(a)).LF()
}

func mermaidFromArchitecture(a *alzlib.Architecture) string {
	sb := strings.Builder{}
	sb.WriteString("flowchart TD\n")

	rootMgs := a.RootMgs()
	slices.SortFunc(rootMgs, sortFuncArchitectureManagementGroup)

	for _, mg := range rootMgs {
		mermaidFromArchitectureRecursion(&sb, mg)
	}

	return sb.String()
}

func mermaidFromArchitectureRecursion(sb *strings.Builder, mg *alzlib.ArchitectureManagementGroup) {
	archs := mg.Archetypes()
	archetypes := make([]string, len(archs))

	for i, a := range archs {
		archetypes[i] = a.Name()
	}

	archetypesStr := strings.Join(archetypes, ", ")
	fmtStr := `  %s["%s
(%s)"]
`
	fmt.Fprintf(sb, fmtStr, mg.ID(), mg.DisplayName(), archetypesStr)
	children := mg.Children()
	slices.SortFunc(children, sortFuncArchitectureManagementGroup)

	for _, child := range children {
		fmt.Fprintf(sb, "  %s --> %s\n", mg.ID(), child.ID())
		mermaidFromArchitectureRecursion(sb, child)
	}
}

// sortFuncArchitectureManagementGroup is a sort function for alzlib.ArchitectureManagementGroup for
// use in
// slices.SortFunc.
func sortFuncArchitectureManagementGroup(a, b *alzlib.ArchitectureManagementGroup) int {
	if a.ID() < b.ID() {
		return -1
	}

	if a.ID() > b.ID() {
		return 1
	}

	return 0
}

// func metadataDependenciesToAlzlibProviderLibRefs(deps alzlib.LibraryReferences) string {
// 	sb := strings.Builder{}
// 	if len(deps) == 0 {
// 		return sb.String()
// 	}
// 	for _, dep := range deps {
// 		switch d := dep.(type) {
// 		case *alzlib.AlzLibraryReference:
// 			sb.WriteString("\n    {\n")
// 			sb.WriteString(fmt.Sprintf("      path = \"%s\"\n", d.Path()))
// 			sb.WriteString(fmt.Sprintf("      ref  = \"%s\"\n", d.Ref()))
// 			sb.WriteString("    }\n")
// 		case *alzlib.CustomLibraryReference:
// 			sb.WriteString("\n    {\n")
// 			sb.WriteString(fmt.Sprintf("      custom_url = \"%s\"\n", d.String()))
// 			sb.WriteString("    }\n")
// 		}

// 	}
// 	return sb.String()
// }

func alzlibReadmeMdPolicyDefaultValues(
	md *markdown.Markdown,
	az *alzlib.AlzLib,
) *markdown.Markdown {
	pdvs := az.PolicyDefaultValues()
	if len(pdvs) == 0 {
		return md
	}

	md = md.H2("Policy Default Values").
		LF().
		PlainText("The following policy default values are available in this library:").
		LF()
	for _, pdv := range pdvs {
		md = md.H3("default name `" + pdv + "`").LF()
		desc := az.PolicyDefaultValue(pdv).Description()

		if desc != "" {
			md = md.PlainText(desc).LF()
		}

		t := markdown.TableSet{
			Header: []string{"Assignment", "Parameter Names"},
			Rows:   [][]string{},
		}
		for _, assignment := range az.PolicyDefaultValue(pdv).Assignments() {
			t.Rows = append(
				t.Rows,
				[]string{
					assignment,
					strings.Join(az.PolicyDefaultValue(pdv).AssignmentParameters(assignment), ", "),
				},
			)
		}

		md = md.Table(t).LF()
	}

	return md
}
