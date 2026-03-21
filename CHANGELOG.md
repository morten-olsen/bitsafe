# Changelog

## [0.2.0](https://github.com/morten-olsen/grimoire/compare/v0.1.0...v0.2.0) (2026-03-21)


### ⚠ BREAKING CHANGES

* **common:** hardcode security parameters and zeroize all credentials

### Features

* **ci:** add FlakeHub publish workflow ([4700e04](https://github.com/morten-olsen/grimoire/commit/4700e047524b259799da0b9e3d156feee9c171e0))
* **ci:** add release-please for automated versioning ([7c41a73](https://github.com/morten-olsen/grimoire/commit/7c41a730176b5dc34a5119da3c7c50ae036f8226))
* **ci:** auto-update Homebrew tap on release ([11ca558](https://github.com/morten-olsen/grimoire/commit/11ca5589842d6d26767fe3c0fe99bbefd7c8ceaf))
* **ci:** implement release pipeline with signing, changelog, and Nix flake ([eb549dc](https://github.com/morten-olsen/grimoire/commit/eb549dced649009a8bdd733385fc48b27e10750e))


### Bug Fixes

* **ci:** remove release-type override from release-please workflow ([0482320](https://github.com/morten-olsen/grimoire/commit/0482320caf224febad9c586b97124a83d8c6a624))
* **ci:** use simple release type for virtual workspace ([0719f0e](https://github.com/morten-olsen/grimoire/commit/0719f0e69746f21a4fa599caf13f3335821c1fee))
* **cli:** reuse password from authorize request when vault is locked ([f949260](https://github.com/morten-olsen/grimoire/commit/f9492601de2959779b4f553ca9105b5c0b4138c1))
* **cli:** use stopReason instead of hookSpecificOutput in stop hook ([ccfaf55](https://github.com/morten-olsen/grimoire/commit/ccfaf5523db5d4d8c959ddc2cf72ab3c517d6a99))
* resolve CI build failures from missing libc dep and unused import ([c74847b](https://github.com/morten-olsen/grimoire/commit/c74847b90f662b05bffb255f08bc4180295f694e))
* resolve clippy warnings across all crates ([8c63f5b](https://github.com/morten-olsen/grimoire/commit/8c63f5bf581d0b0cee53425de35191ff011230b3))


### Security

* **common:** hardcode security parameters and zeroize all credentials ([a96da70](https://github.com/morten-olsen/grimoire/commit/a96da708762fd34b0c2ec12609a6250c3f3e1c0d))
* comprehensive audit fixes across all crates ([2f0304e](https://github.com/morten-olsen/grimoire/commit/2f0304eb08a0733df1da4f0e06da80179fe6ed32))


### Other Changes

* apply cargo fmt formatting across all crates ([437bb57](https://github.com/morten-olsen/grimoire/commit/437bb57c45de83f342ac64cf7a9a61262a62ec4a))
* rename project from BitSafe to Grimoire ([be6fab1](https://github.com/morten-olsen/grimoire/commit/be6fab111bb1d93bb31849a236d04d3fe6451c4b))
