### Agent behaviour (that's you!)

- The agent should ask before making any changes to the codebase.
  If the prompt does not contain a specific request for code changes,
  the agent should respond with guidance and code snippets on how to implement the requested feature or fix the issue.
  It should then ask if the user would like to proceed with the changes to the codebase.

### Code Style

- Use `gofmt` to format your Go code.
- Run `golangci-lint run` to check for linting issues, use with the `--fix` flag to automatically fix issues where possible.
  - Inspect the `.golangci.yml` file in the root of this repo for specific linting rules.
- Each go file must have the following header, followed by a blank line and then the package keyword:
    // Copyright (c) Microsoft Corporation 2025. All rights reserved.
    // SPDX-License-Identifier: MIT
- Each package should have a `doc.go` file that contains the header above, then a blank line and the package-level documentation using the `// Package <name> ...` comment format. Then the package keyword.
- Complex nested if statements should be avoided. Use switch statements or early returns instead.
- All exported functions and types should have comments that explain their purpose.
- Keep the happy path left aligned, and use indentation for error handling or complex logic.

### Comments

- Use comments to explain the purpose of complex logic or non-obvious code.
- Exported functions must have comments that explain their purpose, using the format `// FunctionName does something`.
- Exported types must have comments that explain their purpose, using the format `// TypeName is something`.


### Error Handling

- Use static error types for common errors, such as `var ErrMyCustomError = errors.New("my custom error")`, etc.
- If an error needs additional context, create a NewErrMyCustomError function that returns a wrapped error, e.g.:
    ```go
    func NewErrMyCustomError(msg string) error {
        return fmt.Errorf("%w: %s", ErrMyCustomError, msg)
    }
    ```
- Wrap errors using `errors.Join` (preferred) or `fmt.Errorf("additional context: %w", err)`.

### Context

- All functions that perform operations should accept a `context.Context` parameter in the first position to allow for cancellation and timeouts, as well as logging.

### Testing

- Test assertions and requirements should use the `"github.com/stretchr/testify/assert"`,
and `"github.com/stretchr/testify/require"` packages.
- Use table-driven tests for better organization and readability.
- Unit tests should reside in a file named as per the file containing the code being tested, with the suffix `_test.go`.
- Integration tests should reside in a file named as per the file or package containing the code being tested, with the suffix `_integration_test.go`.
- This package uses concurrency so tests should be run with the `-race` flag to ensure they are thread-safe. This should be done after verifying unit tests pass in isolation.
