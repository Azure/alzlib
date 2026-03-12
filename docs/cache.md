# Built-in Policy Definition Cache

The `alzlib` library supports caching Azure built-in policy definitions and policy set definitions locally. This avoids repeated Azure API calls when initializing the library, which is useful for CI pipelines, local development, and offline scenarios.

## Performance

Benchmarks run on Apple M1 Pro comparing the two initialization paths:

| Metric | With Cache | With Azure Client | Ratio |
|---|---|---|---|
| **Wall time** | **1.20s** | **114.49s** | ~96x faster |
| Memory allocated | 1,406 MB | 716 MB | Cache uses ~2x more |
| Allocations | 11.2M | 7.1M | Cache uses ~1.6x more |

The cache path trades higher memory usage for a ~96x reduction in wall-clock time. The additional memory is transient — definitions not referenced by the library are eligible for garbage collection after initialization.

The cache is loaded lazily: only definitions that are actually referenced by the library's policy assignments are fetched from the cache (or from Azure if missing). The cache reference is retained for the lifetime of AlzLib — call `az.AddCache(nil)` to release it explicitly when no further lookups are needed.

## Creating a Cache File

Use the `alzlibtool` CLI to create a cache file from an authenticated Azure session:

```sh
alzlibtool cache create -o alzlib-cache.json.gz
```

This scans the Azure tenant for all built-in policy definitions and policy set definitions, including historical versions, and writes them to a gzip-compressed JSON file.

Azure credentials are resolved via the standard `ARM_*` / `AZURE_*` environment variables or Azure CLI (`az login`).

### Verbose output

Add `--verbose` to see progress during creation:

```sh
alzlibtool cache create -o alzlib-cache.json.gz --verbose
```

## Inspecting a Cache File

```sh
alzlibtool cache info alzlib-cache.json.gz
```

This displays summary statistics: the number of policy definition names, policy set definition names, and total version counts.

Add `--verbose` to list every cached definition and its versions:

```sh
alzlibtool cache info --verbose alzlib-cache.json.gz
```

## Using a Cache in Go

```go
import (
    "os"

    "github.com/Azure/alzlib"
    "github.com/Azure/alzlib/cache"
)

// Load the cache from a file.
f, err := os.Open("alzlib-cache.json.gz")
if err != nil {
    return err
}
defer f.Close()

c, err := cache.NewCache(f)
if err != nil {
    return err
}

// Register the cache with AlzLib for lazy lookup.
az := alzlib.NewAlzLib(nil)
az.AddCache(c)

// No Azure policy client is needed if the cache covers all
// built-in definitions referenced by the library.
// If a definition is missing from the cache, AlzLib falls back
// to the Azure client (if one has been set via AddPolicyClient).
// The cache is kept until explicitly released — call az.AddCache(nil)
// to allow the garbage collector to reclaim its memory.
```

Definitions are fetched from the cache on demand during `GetDefinitionsFromAzure` (called internally by the deployment package). Only the definitions actually needed are loaded into AlzLib, and deep copies are made of every fetched definition to ensure the cache remains immutable.

## Cache Freshness

The cache is a point-in-time snapshot of Azure built-in definitions. Regenerate it periodically to pick up new or updated definitions. A stale cache is not harmful — `AlzLib` falls back to Azure API calls for any missing definitions, provided a policy client is configured.
