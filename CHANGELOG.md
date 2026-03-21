# Changelog

## [0.2.1](https://github.com/morten-olsen/grimoire/compare/v0.2.0...v0.2.1) (2026-03-21)


### Bug Fixes

* **ci:** escape awk variables in Nix postPatch string ([440c5b9](https://github.com/morten-olsen/grimoire/commit/440c5b983295d1b11a3c26d3407848441f277695))
* **ci:** handle Cargo.lock version drift in Nix build ([a65b5dd](https://github.com/morten-olsen/grimoire/commit/a65b5dda2f70b659bacfade45dc84c77d54243f9))
* **ci:** ignore unfixable SDK transitive advisories in cargo audit ([44e5564](https://github.com/morten-olsen/grimoire/commit/44e556418615ac6e7a35e05e726aa76281596ac3))
* **ci:** remove broken postPatch and sync Cargo.lock in release PR ([a8b542f](https://github.com/morten-olsen/grimoire/commit/a8b542f73f6ac2a59cef9e62078b8817ecade7f2))


### Security

* **auth:** persist password backoff counter across restarts ([51293ff](https://github.com/morten-olsen/grimoire/commit/51293ffa46cac9b27d63614f29f1b5b456e00b53))
* **ci:** add cargo-audit to CI pipeline ([e593343](https://github.com/morten-olsen/grimoire/commit/e5933431a2be3b6e315f8900581d8e2cea26bf35))
* **common:** reject world/group-writable config file and sync docs ([8c11a56](https://github.com/morten-olsen/grimoire/commit/8c11a5604c58f8af9f8aeeb3463cf6a517d218d9))
* **common:** warn on world/group-writable config file ([b44441a](https://github.com/morten-olsen/grimoire/commit/b44441ad53f918d5e00fd81b730899235b66e296))
* **ipc:** add connection limits, timeouts, and reduce message size ([7449a23](https://github.com/morten-olsen/grimoire/commit/7449a239c6e0fc456ffd7f264965cfb510f43504))
* **sdk:** pass Zeroizing&lt;String&gt; through SDK boundary and bound KDF params ([61037d7](https://github.com/morten-olsen/grimoire/commit/61037d7cbfdb5b9e78cd20fca31536a748e8a4ec))
* **service:** make memory hardening fatal, add macOS PT_DENY_ATTACH ([e704431](https://github.com/morten-olsen/grimoire/commit/e704431600684a9556c4259105846d2297f9e9f8))
* **service:** remove --allow-insecure-memory escape hatch ([b351158](https://github.com/morten-olsen/grimoire/commit/b351158bbd2cbdcb7be157cd29ac4153dd656970))
* **service:** remove PATH fallback for prompt binary discovery ([91582a6](https://github.com/morten-olsen/grimoire/commit/91582a6e145f0aaffe0dfcdd3c74a87f011edbbb))
* **ssh:** add UID peer verification to SSH agent socket ([49d2bdf](https://github.com/morten-olsen/grimoire/commit/49d2bdf0b60315113ad08e16363bf494ac520536))
* **ssh:** zeroize SSH private key material after signing ([0a6b9a7](https://github.com/morten-olsen/grimoire/commit/0a6b9a71d6c8cc97d39a20cf6a86579ffd45941a))


### Other Changes

* apply cargo fmt formatting ([288a36d](https://github.com/morten-olsen/grimoire/commit/288a36dc5b98463fe4ccdc71d7f32e46dfa3606c))

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
