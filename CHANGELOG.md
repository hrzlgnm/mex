# Changelog

## [0.3.1](https://github.com/hrzlgnm/mex/compare/v0.3.0...v0.3.1) (2026-11-10)


### Bug Fixes

* merge late subtype PTRs/TXT into live services case-insensitively ([#29](https://github.com/hrzlgnm/mex/issues/29)) ([01f6cd5](https://github.com/hrzlgnm/mex/commit/01f6cd5702f4bacff6d36c9e76da1d9cdbc4e2e2))


### Dependencies

* lock file maintenance ([#31](https://github.com/hrzlgnm/mex/issues/31)) ([013f5f4](https://github.com/hrzlgnm/mex/commit/013f5f4a236e03f6de58ffd28e303cbecb1642cc))

## [0.3.0](https://github.com/hrzlgnm/mex/compare/v0.2.0...v0.3.0) (2026-11-10)


### Features

* publish plain binaries for packaging systems and installers ([#26](https://github.com/hrzlgnm/mex/issues/26)) ([29f8f1e](https://github.com/hrzlgnm/mex/commit/29f8f1eb9cdc07f4a44297b3eed5ac51abe4cccd))


### Dependencies

* update ghcr.io/hrzlgnm/mdns-browser-arch-aur-builder:v1 docker digest to 6db50c1 ([#27](https://github.com/hrzlgnm/mex/issues/27)) ([d04a0a2](https://github.com/hrzlgnm/mex/commit/d04a0a243b016f0913e0f079665ad7b89fc4691a))

## [0.2.0](https://github.com/hrzlgnm/mex/compare/v0.1.1...v0.2.0) (2026-11-09)


### Features

* show own outgoing questions as self rows in Questions pane ([#10](https://github.com/hrzlgnm/mex/issues/10)) ([53434a9](https://github.com/hrzlgnm/mex/commit/53434a990b503ee3805576538e538f0cbf0f94a5))


### Dependencies

* lock file maintenance ([#25](https://github.com/hrzlgnm/mex/issues/25)) ([6e8c6a7](https://github.com/hrzlgnm/mex/commit/6e8c6a7a48501e3e9dad6a7073d50f09bb0a98ae))
* pin dependencies ([#3](https://github.com/hrzlgnm/mex/issues/3)) ([f0996d9](https://github.com/hrzlgnm/mex/commit/f0996d98672516d1df1b1a72cb1f1f7494682aa7))
* update actions/checkout action to v7 ([#17](https://github.com/hrzlgnm/mex/issues/17)) ([56180cd](https://github.com/hrzlgnm/mex/commit/56180cd0afc267f0c54e8dd99e82bc17f1a9a3ac))
* update actions/upload-artifact action to v7 ([#18](https://github.com/hrzlgnm/mex/issues/18)) ([c5da384](https://github.com/hrzlgnm/mex/commit/c5da38461a036cb852c11a505425ff913d1152e7))
* update rust crate crossterm to 0.29 ([#14](https://github.com/hrzlgnm/mex/issues/14)) ([e872025](https://github.com/hrzlgnm/mex/commit/e87202593498978327996111f23b8d8cc47f935e))
* update rust crate hickory-proto to v0.26 ([#20](https://github.com/hrzlgnm/mex/issues/20)) ([12e45ae](https://github.com/hrzlgnm/mex/commit/12e45ae77431245c86f8b54e39f024076fa1ecdf))
* update rust crate log to v0.4.35 ([#11](https://github.com/hrzlgnm/mex/issues/11)) ([61aa2f4](https://github.com/hrzlgnm/mex/commit/61aa2f443003872d777fbe323f7eb8d605cad204))
* update rust crate ratatui to v0.30 ([#21](https://github.com/hrzlgnm/mex/issues/21)) ([47b8339](https://github.com/hrzlgnm/mex/commit/47b833999448ca0f97b6a421c4362506bf18e1e2))
* update rust crate socket-pktinfo to v0.4.1 ([#12](https://github.com/hrzlgnm/mex/issues/12)) ([e4f5b76](https://github.com/hrzlgnm/mex/commit/e4f5b764378e07e481c82231b1bc8affbcd554de))
* update rust crate winresource to v0.1.34 ([#23](https://github.com/hrzlgnm/mex/issues/23)) ([aa888d7](https://github.com/hrzlgnm/mex/commit/aa888d7495a64c96ed5c9da16025510c3fa482da))


### Documentation

* require conventional commits and pull requests ([#9](https://github.com/hrzlgnm/mex/issues/9)) ([79d1317](https://github.com/hrzlgnm/mex/commit/79d131733754f7eb1dc7b3c7b690908e023f15e3))


### Continuous Integration

* approve bot PRs and publish source checksums ([#6](https://github.com/hrzlgnm/mex/issues/6)) ([0c2aac6](https://github.com/hrzlgnm/mex/commit/0c2aac6de5b657b4a50c96ec9a559276cbb00752))
* approve release PR runs on every push ([#8](https://github.com/hrzlgnm/mex/issues/8)) ([00345e4](https://github.com/hrzlgnm/mex/commit/00345e4950bf33d7a9d1c2fdaeb405c5f3289e88))
* build auditable binaries and attest provenance in CI ([#24](https://github.com/hrzlgnm/mex/issues/24)) ([8d8de61](https://github.com/hrzlgnm/mex/commit/8d8de616e7a9c71fa9c5d7671bb7fff9e2a02510))
* cache builds with sccache ([#7](https://github.com/hrzlgnm/mex/issues/7)) ([dc1246f](https://github.com/hrzlgnm/mex/commit/dc1246f536c9d2e4e6008d0dcb0b5ef4c548a5bb))
* port lockfile-fresh check from mdns-tui-browser ([#13](https://github.com/hrzlgnm/mex/issues/13)) ([df7f413](https://github.com/hrzlgnm/mex/commit/df7f4139adace12aa6636480fe99aed8caeb8124))
* port multi-target builds and packaging assets from mdns-tui-browser ([#22](https://github.com/hrzlgnm/mex/issues/22)) ([c71ef20](https://github.com/hrzlgnm/mex/commit/c71ef2042ab2cc6fcfb90c79ff0966f1da7762c4))
* port typos check from mdns-tui-browser ([#19](https://github.com/hrzlgnm/mex/issues/19)) ([5546774](https://github.com/hrzlgnm/mex/commit/5546774701a9db7b303153599222a1819a573dd4))

## [0.1.1](https://github.com/hrzlgnm/mex/compare/v0.1.0...v0.1.1) (2026-11-09)


### Documentation

* document CLI flags and current key bindings ([42fb323](https://github.com/hrzlgnm/mex/commit/42fb323bcd0db331c7780b376d5f814ebd35b63a))


### Continuous Integration

* add CI and release workflows ([97ca416](https://github.com/hrzlgnm/mex/commit/97ca416456bb2d1d0d4d20a5f39f090e27e5fccc))
* fix status check and add renovate config ([#2](https://github.com/hrzlgnm/mex/issues/2)) ([8d71cd8](https://github.com/hrzlgnm/mex/commit/8d71cd88712450c85ee36d6ef1ed682f99711001))
