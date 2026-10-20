# i1n1-engine

AArch64 interpreter/MMU/PAC engine libraries and native broker (standalone CMake project, no i1n1 dependencies).

Experimental, build-only source release: sources, headers and CMake files for the libraries and tools
of this module. No tests, firmware, Apple software or guest images are included, and no complete guest
boot is claimed.

## Dependencies

None (no other i1n1 repository is required).

## Build

```sh
cmake -S i1n1-engine -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

## Supported hosts and limitations

- Verified build environment: macOS on arm64, Apple clang 21, CMake 4.4, Ninja, C11, `BUILD_TESTING=OFF`.
  Other hosts and compilers have not been verified for this release.
- The build hardcodes `-Werror`; there is no option to disable warnings as errors.
- Unsupported instructions, registers or devices are reported as deterministic stops by the source, not
  emulated; this release is a build of that source, not evidence of a working guest.
- Target names keep the engine's original `ocnext_` prefix and the shared library keeps its original output name.

## License

GPL-2.0-only for project-authored material; see `COPYING` and `LICENSE`; bundled third-party components are listed in `NOTICE.md`.
