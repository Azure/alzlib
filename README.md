# alzlib - a go module for reading Azure Landing Zones Terraform module lib definitions

[![Go test](https://github.com/matt-FFFFFF/alzlib/actions/workflows/go-test.yml/badge.svg)](https://github.com/matt-FFFFFF/alzlib/actions/workflows/go-test.yml) [![codecov](https://codecov.io/gh/matt-FFFFFF/alzlib/branch/main/graph/badge.svg?token=8A28XRERB2)](https://codecov.io/gh/matt-FFFFFF/alzlib)

This module provides a go library for reading [Azure Landing Zones](https://github.com/Azure/terraform-azurerm-caf-enterprise-scale) Terraform module lib definitions.

It uses the Azure SDK for Go to get the data types required:

* [github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy](https://github.com/Azure/azure-sdk-for-go/tree/main/sdk/resourcemanager/resources/armpolicy)

## Usage

See the Example test funcs in [alzlib_test.go](alzlib_test.go) for usage examples.
