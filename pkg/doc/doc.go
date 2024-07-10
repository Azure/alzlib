package doc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Azure/alzlib"
	"github.com/nao1215/markdown"
)

type metadata struct {
	Path         string   `json:"path"`
	DisplayName  string   `json:"display_name"`
	Description  string   `json:"description"`
	Dependencies []string `json:"dependencies"`
}

func AlzlibReadmeMd(ctx context.Context, path string, w io.Writer) error {
	dirFs := os.DirFS(path)
	az := alzlib.NewAlzLib(nil)
	if err := az.Init(ctx, dirFs); err != nil {
		return fmt.Errorf("doc.AlzlibReadmeMd: failed to initialize alzlib: %w", err)
	}

	metadataFile, err := os.ReadFile(filepath.Join(path, "metadata.json"))
	if err != nil {
		return fmt.Errorf("doc.AlzlibReadmeMd: failed to read metadata.json: %w", err)
	}
	var metad metadata
	json.Unmarshal(metadataFile, &metad)
	md := markdown.NewMarkdown(w)
	return md.H1f("%s (%s)", metad.DisplayName, metad.Path).LF().
		PlainText(metad.Description).LF().
		H2("Dependencies").LF().
		BulletList(metad.Dependencies...).LF().
		H2("Contents").LF().
		H3("Policy Definitions").LF().
		BulletList(az.PolicyDefinitions()...).LF().
		H3("Policy Set Definitions").LF().
		BulletList(az.PolicySetDefinitions()...).LF().
		H3("Policy Assignments").LF().
		BulletList(az.PolicyAssignments()...).LF().
		H3("Role Definitions").LF().
		BulletList(az.RoleDefinitions()...).LF().
		H2("Archetypes").LF().
		BulletList(az.Archetypes()...).LF().
		H2("Architectures").LF().
		BulletList(az.Architectures()...).LF().
		H2("Policy Default Values").LF().
		BulletList(az.PolicyDefaultValues()...).Build()
}
