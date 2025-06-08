### Code Style

- Use `gofmt` to format your Go code.
- Run `golangci-lint run` to check for linting issues, use with the `--fix` flag to automatically fix issues where possible.
  - Inspect the `.golangci.yml` file in the root of this repo for specific linting rules.
- Each package should have a `doc.go` file that contains package-level documentation using the `// Package <name> ...` comment format.
- Each go file must have the following header, followed by a blank line and then the package keyword:
    // Copyright (c) Microsoft Ltd 2025. All rights reserved.
    // SPDX-License-Identifier: MIT
- Complex nested if statements should be avoided. Use switch statements or early returns instead.
- All exported functions and types should have comments that explain their purpose.
- Keep the happy path left aligned, and use indentation for error handling or complex logic.

### Error Handling

- Use static error types for common errors, e.g., `var ErrMyCustomError = errors.New("my custom error")`.
- Wrap errors using `errors.Join` (preferred) or `fmt.Errorf("additional context: %w", err)`.

### Testing

- Test assertions and requirements should use the `"github.com/stretchr/testify/assert"`,
and `"github.com/stretchr/testify/require"` packages.
- Use table-driven tests for better organization and readability.
- Unit tests should reside in a file named as per the file containing the code being tested, with the suffix `_test.go`.
- Integration tests should reside in a file named as per the file or package containing the code being tested, with the suffix `_integration_test.go`.
