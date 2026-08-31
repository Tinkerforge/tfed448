# tfed448

`tfed448` is a collection of functions for PureEd448 signatures and SHAKE256. It uses
a reduced 32-bit source set generated from libdecaf v1.0.3 and is
intended ESP32 firmwares with mbedtls.

## libdecaf

The included libdecaf files derive from commit
`e5cc6240690d3ffdfcbdb1e4e851954b789cd5d9` (tag `v1.0.3`).

## Build And Test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## Licensing

Tinkerforge-authored wrapper and build files are licensed under the GNU Lesser
General Public License, version 2.1 or later. Imported libdecaf files retain
their upstream notices and are covered by `LICENSE.libdecaf.txt`.
