// Package doc contains the types and methods for generating documentation from an Alzlib library member.
package doc

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/Azure/alzlib"
	"github.com/nao1215/markdown"
)

func AlzlibReadmeMd(ctx context.Context, w io.Writer, fs ...fs.FS) error {
	az := alzlib.NewAlzLib(nil)
	if err := az.Init(ctx, fs...); err != nil {
		return fmt.Errorf("doc.AlzlibReadmeMd: failed to initialize alzlib: %w", err)
	}

	metadataS := az.Metadata()
	metad := metadataS[len(metadataS)-1]

	path := os.Getenv("ALZLIB_PATH")
	md := markdown.NewMarkdown(w)

	md = alzlibReadmeMdTitle(md, metad)
	md = alzlibReadmeMdDependencies(md, metad.Dependencies())
	md = alzlibReadmeMdUsage(md, metad.Dependencies(), path)
	md = alzlibReadmeMdArchitectures(md, az)
	md = alzlibReadmeMdArchetypes(md, az)
	md = md.HorizontalRule()
	md = alzlibReadmeMdContents(md, az)

	return md.Build()
}

func alzlibReadmeMdTitle(md *markdown.Markdown, metad *alzlib.Metadata) *markdown.Markdown {
	return md.H1f("%s (%s)", metad.Name(), metad.DisplayName()).LF().
		PlainText(metad.Description()).LF()
}

func alzlibReadmeMdDependencies(md *markdown.Markdown, deps []*alzlib.MetadataDependency) *markdown.Markdown {
	if len(deps) == 0 {
		return md
	}
	md = md.H2("Dependencies").LF()
	for _, dep := range deps {
		md = md.BulletList("%s", dep.String())
	}
	return md.LF()
}

func alzlibReadmeMdUsage(md *markdown.Markdown, deps []*alzlib.MetadataDependency, path string) *markdown.Markdown {
	return md.H2("Usage").LF().
		CodeBlocks(markdown.SyntaxHighlight("terraform"), fmt.Sprintf(`provider "alz" {
  library_references = [%s
    {
      path = "%s"
      tag  = "0000.00.0" # Replace with the desired version
    }
  ]
}`, metadataDependenciesToAlzlibProviderLibRefs(deps), path)).LF()
}

func alzlibReadmeMdArchitectures(md *markdown.Markdown, az *alzlib.AlzLib) *markdown.Markdown {
	archs := az.Architectures()
	if len(archs) == 0 {
		return md
	}
	md = md.H2("Architectures").LF().
		PlainText("The following architectures are available in this library:").LF()
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
			md = md.H3("`" + archetype.Name() + "`").LF()
			if len(pds) > 0 {
				md.H4("Policy Definitions").LF().
					Details(fmt.Sprintf("%d policy definitions", archetype.PolicyDefinitions.Cardinality()), "\n- "+strings.Join(pds, "\n- ")).LF()
			}
			if len(psds) > 0 {
				md = md.H4("Policy Set Definitions").LF().
					Details(fmt.Sprintf("%d policy set definitions", archetype.PolicySetDefinitions.Cardinality()), "\n- "+strings.Join(psds, "\n- ")).LF()
			}
			if len(pas) > 0 {
				md = md.H4("Policy Assignments").LF().
					Details(fmt.Sprintf("%d policy assignments", archetype.PolicyAssignments.Cardinality()), "\n- "+strings.Join(pas, "\n- ")).LF()
			}
			if len(rds) > 0 {
				md = md.H4("Role Definitions").LF().
					Details(fmt.Sprintf("%d role definitions", archetype.RoleDefinitions.Cardinality()), "\n- "+strings.Join(rds, "\n- ")).LF()
			}
		}
	}
	return md
}

func alzlibReadmeMdContents(md *markdown.Markdown, az *alzlib.AlzLib) *markdown.Markdown {
	md = md.H2("Contents").LF()
	if len(az.PolicyDefinitions()) > 0 {
		md = md.H3("Policy Definitions").LF().
			Details(fmt.Sprintf("%d policy definitions", len(az.PolicyDefinitions())), "\n- "+strings.Join(az.PolicyDefinitions(), "\n- ")).LF()
	}
	if len(az.PolicySetDefinitions()) > 0 {
		md = md.H3("Policy Set Definitions").LF().
			Details(fmt.Sprintf("%d policy set definitions", len(az.PolicySetDefinitions())), "\n- "+strings.Join(az.PolicySetDefinitions(), "\n- ")).LF()
	}
	if len(az.PolicyAssignments()) > 0 {
		md = md.H3("Policy Assignments").LF().
			Details(fmt.Sprintf("%d policy assignments", len(az.PolicyAssignments())), "\n- "+strings.Join(az.PolicyAssignments(), "\n- ")).LF()
	}
	if len(az.RoleDefinitions()) > 0 {
		md = md.H3("Role Definitions").LF().
			Details(fmt.Sprintf("%d role definitions", len(az.RoleDefinitions())), "\n- "+strings.Join(az.RoleDefinitions(), "\n- ")).LF()
	}
	return md
}

func alzlibReadmeMdArchitecture(md *markdown.Markdown, a *alzlib.Architecture) *markdown.Markdown {
	return md.H3("`"+a.Name()+"`").LF().
		Note("This hierarchy will be deployed as a child of the user-supplied root management group.").LF().
		CodeBlocks("mermaid", mermaidFromArchitecture(a)).LF()
}

func mermaidFromArchitecture(a *alzlib.Architecture) string {
	sb := strings.Builder{}
	sb.WriteString("flowchart TD\n")
	for _, mg := range a.RootMgs() {
		mermaidFromArchitectureRecursion(&sb, mg)
	}
	return sb.String()
}

func mermaidFromArchitectureRecursion(sb *strings.Builder, mg *alzlib.ArchitectureManagementGroup) {
	archetypes := make([]string, len(mg.Archetypes()))
	for i, a := range mg.Archetypes() {
		archetypes[i] = a.Name()
	}
	archetypesStr := strings.Join(archetypes, ", ")
	sb.WriteString(fmt.Sprintf("  %s[\"%s\\n(%s)\"]\n", mg.Id(), mg.DisplayName(), archetypesStr))
	for _, child := range mg.Children() {
		sb.WriteString(fmt.Sprintf("  %s --> %s\n", mg.Id(), child.Id()))
		mermaidFromArchitectureRecursion(sb, child)
	}
}

func metadataDependenciesToAlzlibProviderLibRefs(deps []*alzlib.MetadataDependency) string {
	sb := strings.Builder{}
	if len(deps) == 0 {
		return sb.String()
	}
	for _, dep := range deps {
		sb.WriteString("\n    {\n")
		sb.WriteString(fmt.Sprintf("      path = \"%s\"\n", dep.Path()))
		sb.WriteString(fmt.Sprintf("      tag  = \"%s\"\n", dep.Tag()))
		sb.WriteString("    }\n")
	}
	return sb.String()
}
