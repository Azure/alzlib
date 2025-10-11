# alzlib

[![Go test](https://github.com/Azure/alzlib/actions/workflows/go-test.yml/badge.svg)](https://github.com/Azure/alzlib/actions/workflows/go-test.yml) [![codecov](https://codecov.io/gh/Azure/alzlib/branch/main/graph/badge.svg?token=8A28XRERB2)](https://codecov.io/gh/Azure/alzlib)

This module provides a go library for reading [Azure Landing Zones Library](https://github.com/Azure/azure-landing-zones-library) definitions.

## Installation

To install `alzlib`, use the following `go get` command:

```bash
go get -u github.com/Azure/alzlib
```

## Usage

See the examples in the `integrationtest/examples_test.go` file for usage examples.

We recommend adding `.alzlib` to your `.gitignore` file to avoid committing the library cache to your repository.

## Why?

Managing Azure Policy at-scale can be challenging. This module helps by providing a way to programmatically access and manage Azure Policy definitions, assignments, and initiatives from the [Azure Landing Zones Library](https://github.com/Azure/Azure-Landing-Zones-Library).

Key benefits include:

- Ensuring that the definition in your policy assignment is assignable. This means that it is built-in, or in-scope for the assignment (in this management group or a parent).
- Ensuring that all of your policy assignment parameters are valid, and that they exist in the definition.
- Correctly calculating the role assignments required for `Modify` and `DeployIfNotExists` policies.
  - For this we to get all the definitions that are assigned, and look at the `roleDefinitionIds` property of the policy definition.
  - We assign roles at the scope of the policy assignment, and for any parameter value that has the `assignPermissions` metadata property set to `true`. This supports a least-privilege model and ensures that the role assignment is removed either when the resource is deleted, or when the policy assignment is removed.

The Library is a way of defining and customizing a management group hierarchy and associated policies for an organization. It is designed to be a starting point for organizations to build their own governance model. This module provides a way to consume the Library in a programmatic way, allowing for easier integration into existing tooling and processes. Typically this is infrastructure as code tooling, such as a Terraform provider or Pulumi package.

## Configuration

The module uses the following environment variables:

- `ALZLIB_DIR`: The local temporary directory where the libraries will be cloned. Default is `.alzlib`
- `ALZLIB_LIBRARY_GIT_URL`: The URL of the Azure Landing Zones Library repository. Default is `github.com/Azure/Azure-Landing-Zones-Library`

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit <https://cla.opensource.microsoft.com>.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
