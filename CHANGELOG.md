# Changelog

## [0.15.2](https://github.com/hrzlgnm/mex/compare/v0.15.1...v0.15.2) (2026-11-13)


### Bug Fixes

* bound pending mDNS address state ([#177](https://github.com/hrzlgnm/mex/issues/177)) ([37d594e](https://github.com/hrzlgnm/mex/commit/37d594e5ae4d409e937da0a914b77fec57f4eb54))
* stabilize host grouping when a service advertises multiple SRV targets ([#173](https://github.com/hrzlgnm/mex/issues/173)) ([735a821](https://github.com/hrzlgnm/mex/commit/735a821b72377705aed18a4e0912804310cbb3b7))


### Dependencies

* lock file maintenance ([#175](https://github.com/hrzlgnm/mex/issues/175)) ([26911c0](https://github.com/hrzlgnm/mex/commit/26911c0b6bb9df20b7d097995dd1d8b109a233db))

## [0.15.1](https://github.com/hrzlgnm/mex/compare/v0.15.0...v0.15.1) (2026-11-13)


### Bug Fixes

* keep DUE blank on foreign question rows ([#170](https://github.com/hrzlgnm/mex/issues/170)) ([ba6a107](https://github.com/hrzlgnm/mex/commit/ba6a10710fed780f5e399b7fa3bf6aa0ac933501))
* make Questions pane LAST reflect the row's own query activity ([#163](https://github.com/hrzlgnm/mex/issues/163)) ([20e7d08](https://github.com/hrzlgnm/mex/commit/20e7d086715b3999168fd33cdaa311e731e0ed3b))


### Dependencies

* lock file maintenance ([#171](https://github.com/hrzlgnm/mex/issues/171)) ([9c04d2e](https://github.com/hrzlgnm/mex/commit/9c04d2e7e15251fe6c9cbe82caee0cd798c81f0c))


### Documentation

* require agents to work in a fresh worktree from main ([#164](https://github.com/hrzlgnm/mex/issues/164)) ([e6c0a72](https://github.com/hrzlgnm/mex/commit/e6c0a72c23714a96befbc49f18b48c703ded0833))
* require Closes #&lt;issue&gt; ref on PRs implementing an issue ([#169](https://github.com/hrzlgnm/mex/issues/169)) ([9affc81](https://github.com/hrzlgnm/mex/commit/9affc8136891ab1e53ede8542fbe7e4a88be3181))


### Code Refactoring

* use AnomalyKind enum instead of string kinds ([#167](https://github.com/hrzlgnm/mex/issues/167)) ([05eb609](https://github.com/hrzlgnm/mex/commit/05eb609ea437bb586b934c53c2159d6f4b5fe896))

## [0.15.0](https://github.com/hrzlgnm/mex/compare/v0.14.0...v0.15.0) (2026-11-13)


### Features

* add --log-level command line switch ([#160](https://github.com/hrzlgnm/mex/issues/160)) ([b3028d0](https://github.com/hrzlgnm/mex/commit/b3028d0913ae7275c28adf7ff1eb7e8f7876c0cd))

## [0.14.0](https://github.com/hrzlgnm/mex/compare/v0.13.0...v0.14.0) (2026-11-13)


### Features

* default log directory with size-based rotation ([#148](https://github.com/hrzlgnm/mex/issues/148)) ([0440173](https://github.com/hrzlgnm/mex/commit/04401731c5fb6e3b6e154652144cb8f3c32317c5))
* flag non-UTF-8 names as anomaly (RFC 6762 §16) ([#141](https://github.com/hrzlgnm/mex/issues/141)) ([f1e91c5](https://github.com/hrzlgnm/mex/commit/f1e91c5a6ab9caec8f4ee3b7b30b6835fc5e7bbc))
* LAST/DUE query columns and optional file logging ([#147](https://github.com/hrzlgnm/mex/issues/147)) ([765d016](https://github.com/hrzlgnm/mex/commit/765d016b26728be16a87e74a9c074119d7ae540e))
* per-interest query provenance and authoritative dump state ([#146](https://github.com/hrzlgnm/mex/issues/146)) ([b17a274](https://github.com/hrzlgnm/mex/commit/b17a274c2a906a86021933fcba98942b74f4981f))
* port DNS wire codec from hickory-proto to simple-dns ([#140](https://github.com/hrzlgnm/mex/issues/140)) ([bbbdcc6](https://github.com/hrzlgnm/mex/commit/bbbdcc62a9b182c5a489cb55293aa660442fb347))


### Bug Fixes

* add top-level permissions to reusable workflows (CKV2_GHA_1) ([#153](https://github.com/hrzlgnm/mex/issues/153)) ([537457c](https://github.com/hrzlgnm/mex/commit/537457cbb04b6c5aa063a68b3f8415e19b3cdd1d))


### Dependencies

* lock file maintenance ([#158](https://github.com/hrzlgnm/mex/issues/158)) ([c6609f5](https://github.com/hrzlgnm/mex/commit/c6609f51882ceec6644a6a911085c541c64a23c8))


### Documentation

* require one logical change per branch/PR ([#155](https://github.com/hrzlgnm/mex/issues/155)) ([e555ff6](https://github.com/hrzlgnm/mex/commit/e555ff6ae294b2a8cca6459d3df93dd2fc759839))
* wrap long Cargo.toml comment lines and fix indentation ([#145](https://github.com/hrzlgnm/mex/issues/145)) ([80aaba6](https://github.com/hrzlgnm/mex/commit/80aaba628342c50ce0b5a1fa2df03240facb10f9))


### Code Refactoring

* deduplicate rec/rec_with test helpers in anomalies ([#154](https://github.com/hrzlgnm/mex/issues/154)) ([adb20a5](https://github.com/hrzlgnm/mex/commit/adb20a591a9da818a157db23e8997ebde222120f))
* remove top-level permissions from reusable workflows ([#157](https://github.com/hrzlgnm/mex/issues/157)) ([5b3ed36](https://github.com/hrzlgnm/mex/commit/5b3ed3680d19e5bdb6514bc7e430e29311cf87a8))

## [0.13.0](https://github.com/hrzlgnm/mex/compare/v0.12.0...v0.13.0) (2026-11-12)


### Features

* source-first, concise anomaly lines ([#128](https://github.com/hrzlgnm/mex/issues/128)) ([b68c065](https://github.com/hrzlgnm/mex/commit/b68c065c30bb595b5242f35736417e4b01869671))


### Bug Fixes

* ignore reverse-mapping PTRs for service browsing ([#130](https://github.com/hrzlgnm/mex/issues/130)) ([3a1e88a](https://github.com/hrzlgnm/mex/commit/3a1e88a1d516585c8c6845c30b931886251299c8))

## [0.12.0](https://github.com/hrzlgnm/mex/compare/v0.11.1...v0.12.0) (2026-11-12)


### Features

* attach RFC requirement to every finding ([#119](https://github.com/hrzlgnm/mex/issues/119)) ([5ee0e07](https://github.com/hrzlgnm/mex/commit/5ee0e07d62548b55b07dda44b05b3c65e86f7f86))
* flag subtypes in service enumeration ([#121](https://github.com/hrzlgnm/mex/issues/121)) ([0dcf6bc](https://github.com/hrzlgnm/mex/commit/0dcf6bcaec5c043c71213df9578a916f7c7849a5))
* track packet context for each record ([#120](https://github.com/hrzlgnm/mex/issues/120)) ([8171662](https://github.com/hrzlgnm/mex/commit/8171662509e4c713242cd860f070b3ce244b5350))


### Bug Fixes

* gate cache-flush verdict on confirmed multicast ([#123](https://github.com/hrzlgnm/mex/issues/123)) ([195bf8d](https://github.com/hrzlgnm/mex/commit/195bf8d26287c2755d9537797fe9fec707534f2a))
* gate unicast-leak verdict on confirmed multicast ([#122](https://github.com/hrzlgnm/mex/issues/122)) ([c641c21](https://github.com/hrzlgnm/mex/commit/c641c21e12248379d227be50d733757e53198456))
* reclassify SHOULD-deviations to Info ([#118](https://github.com/hrzlgnm/mex/issues/118)) ([04eb9a9](https://github.com/hrzlgnm/mex/commit/04eb9a9bf4a926bf30ba539b87ac3817eeb91ee4))

## [0.11.1](https://github.com/hrzlgnm/mex/compare/v0.11.0...v0.11.1) (2026-11-12)


### Bug Fixes

* label metrics anomaly count row as summary ([#110](https://github.com/hrzlgnm/mex/issues/110)) ([b913b25](https://github.com/hrzlgnm/mex/commit/b913b25ec5c2ab334c4da50ea8bae43920b8af03))

## [0.11.0](https://github.com/hrzlgnm/mex/compare/v0.10.0...v0.11.0) (2026-11-12)


### Features

* list full service findings in anomalies pane with cursor marker ([#105](https://github.com/hrzlgnm/mex/issues/105)) ([518a4c4](https://github.com/hrzlgnm/mex/commit/518a4c4541237b9161da81bfcccbe9c9e37f798b))
* name gone rows and pin pane freshness ([#102](https://github.com/hrzlgnm/mex/issues/102)) ([e2fa1f5](https://github.com/hrzlgnm/mex/commit/e2fa1f5e9bff657391203981f261fab098611b70))
* rework metrics anomalies display and TTL anomaly marks ([#92](https://github.com/hrzlgnm/mex/issues/92)) ([1d8ff22](https://github.com/hrzlgnm/mex/commit/1d8ff22bac4d9edaab5b81f4a592a90e5c68e40d))
* show highlighted record anomalies in new pane ([#98](https://github.com/hrzlgnm/mex/issues/98)) ([2312c51](https://github.com/hrzlgnm/mex/commit/2312c515bc4aa76c7e4722639bdaff689af76203))
* show question and service-level findings in anomalies pane ([#100](https://github.com/hrzlgnm/mex/issues/100)) ([87c137e](https://github.com/hrzlgnm/mex/commit/87c137e68daabbbb54d045b6c3f26f9e6b683244))


### Bug Fixes

* exclude reverse PTRs from 4500s base TTL expectation ([#90](https://github.com/hrzlgnm/mex/issues/90)) ([e1f9e57](https://github.com/hrzlgnm/mex/commit/e1f9e57e1345da7bc734b357ddfabdafca6e26db))


### Dependencies

* lock file maintenance ([#103](https://github.com/hrzlgnm/mex/issues/103)) ([0396b28](https://github.com/hrzlgnm/mex/commit/0396b280a6af28f8a04a889876ede9f41f56492a))
* update rust crate socket-pktinfo to v0.4.2 ([#99](https://github.com/hrzlgnm/mex/issues/99)) ([316791e](https://github.com/hrzlgnm/mex/commit/316791e9269d27838de41644857e5f568a0c3540))


### Documentation

* document metrics overlay scroll keys, fix pan step comment ([#93](https://github.com/hrzlgnm/mex/issues/93)) ([037fb06](https://github.com/hrzlgnm/mex/commit/037fb069f94163d71456aedbb7992f869e007e9d))
* document the anomaly detector in the README ([#108](https://github.com/hrzlgnm/mex/issues/108)) ([0c54d55](https://github.com/hrzlgnm/mex/commit/0c54d55713606477746710bb5525a977751df1eb))
* mention anomaly detection in every summary and the man page ([#109](https://github.com/hrzlgnm/mex/issues/109)) ([dd3e232](https://github.com/hrzlgnm/mex/commit/dd3e232662d8fd38085446519d9452982160e743))


### Tests

* pin anomalies pane mouse and resize integration ([#101](https://github.com/hrzlgnm/mex/issues/101)) ([e01e479](https://github.com/hrzlgnm/mex/commit/e01e479ae7bdca2156062a41d93ee69a28527852))

## [0.10.0](https://github.com/hrzlgnm/mex/compare/v0.9.0...v0.10.0) (2026-11-11)


### Features

* distribute via Homebrew tap + cask ([#81](https://github.com/hrzlgnm/mex/issues/81)) ([45e84fd](https://github.com/hrzlgnm/mex/commit/45e84fda0bbb6d7581b4282783358e76238e7dd7))
* flag observed questions for unicast-only types ([#88](https://github.com/hrzlgnm/mex/issues/88)) ([b42acdf](https://github.com/hrzlgnm/mex/commit/b42acdfaa98f1c2360d8b088fa3cf018fd5dbb5e))


### Bug Fixes

* mark all serial variants of live SOA unicast leaks ([#86](https://github.com/hrzlgnm/mex/issues/86)) ([ce3a01f](https://github.com/hrzlgnm/mex/commit/ce3a01f7779b5337b2e060b35c951e7341ea6775))


### Code Refactoring

* centralize unicast-only verdict for answers ([#87](https://github.com/hrzlgnm/mex/issues/87)) ([d49c2fb](https://github.com/hrzlgnm/mex/commit/d49c2fb3ffaa058cd35ed6857d83ef4ae24a21d4))

## [0.9.0](https://github.com/hrzlgnm/mex/compare/v0.8.0...v0.9.0) (2026-11-11)


### Features

* select specific network interfaces via -i/--interfaces ([#80](https://github.com/hrzlgnm/mex/issues/80)) ([527b2e7](https://github.com/hrzlgnm/mex/commit/527b2e7bfe1c21e0aaba992037cec0e544f8d0c8))


### Documentation

* document measured release profile gains ([#75](https://github.com/hrzlgnm/mex/issues/75)) ([394a7e0](https://github.com/hrzlgnm/mex/commit/394a7e01a2fc2c8850f77138fb0826ec39ba359e))
* record hickory-proto codec decision ([#77](https://github.com/hrzlgnm/mex/issues/77)) ([b618797](https://github.com/hrzlgnm/mex/commit/b6187973f478769079f127d621cdead736bceb1f))

## [0.8.0](https://github.com/hrzlgnm/mex/compare/v0.7.0...v0.8.0) (2026-11-11)


### Features

* add RFC anomaly detection ([#73](https://github.com/hrzlgnm/mex/issues/73)) ([b09a8e7](https://github.com/hrzlgnm/mex/commit/b09a8e7917acd88d758aa1820f69cc939f0b1046))

## [0.7.0](https://github.com/hrzlgnm/mex/compare/v0.6.2...v0.7.0) (2026-11-11)


### Features

* experimental mex state dump (Ctrl+J) ([#70](https://github.com/hrzlgnm/mex/issues/70)) ([d46fd6a](https://github.com/hrzlgnm/mex/commit/d46fd6a5c3b9b5491bb3c56354f7011841777264))

## [0.6.2](https://github.com/hrzlgnm/mex/compare/v0.6.1...v0.6.2) (2026-11-11)


### Bug Fixes

* fan out A/AAAA answers to every service sharing a hostname ([#68](https://github.com/hrzlgnm/mex/issues/68)) ([ec31507](https://github.com/hrzlgnm/mex/commit/ec31507f2a58ec06f223963d984313ca5a6d37d9))

## [0.6.1](https://github.com/hrzlgnm/mex/compare/v0.6.0...v0.6.1) (2026-11-11)


### Bug Fixes

* fall back to self-stop without job-control separation ([#63](https://github.com/hrzlgnm/mex/issues/63)) ([5c7a51e](https://github.com/hrzlgnm/mex/commit/5c7a51e9cc842bd4940a485204f9983ab2a65270))

## [0.6.0](https://github.com/hrzlgnm/mex/compare/v0.5.1...v0.6.0) (2026-11-11)


### Features

* suspend to shell with Ctrl+Z on unix ([#62](https://github.com/hrzlgnm/mex/issues/62)) ([0c36e03](https://github.com/hrzlgnm/mex/commit/0c36e03654330a026ec0dfb7ffb64b772db9e0da))


### Bug Fixes

* bold hex body while hex pane focused ([#61](https://github.com/hrzlgnm/mex/issues/61)) ([69025e5](https://github.com/hrzlgnm/mex/commit/69025e55ac7cc4242c455f65b88c510c98807065))
* keep Answers marker visible when Hosts pane focused ([#56](https://github.com/hrzlgnm/mex/issues/56)) ([6f06a27](https://github.com/hrzlgnm/mex/commit/6f06a27b59bb6d04b99b88cf1286a44ebed17ff5))
* keep Questions marker visible when Hosts pane focused ([#59](https://github.com/hrzlgnm/mex/issues/59)) ([f4b97cf](https://github.com/hrzlgnm/mex/commit/f4b97cf0cb52641dab35e1bdfb23a035e91c37ac))
* self question hex title matches remote QRY format ([#55](https://github.com/hrzlgnm/mex/issues/55)) ([951398b](https://github.com/hrzlgnm/mex/commit/951398bb8e614adbab4fd0645647bb75b231a974))

## [0.5.1](https://github.com/hrzlgnm/mex/compare/v0.5.0...v0.5.1) (2026-11-11)


### Bug Fixes

* left-align TXT child rows in Answers table ([#50](https://github.com/hrzlgnm/mex/issues/50)) ([53e8298](https://github.com/hrzlgnm/mex/commit/53e8298d38fbb1a754fdd386b613721edf680009))
* match AUR pkgdesc to repo description ([#48](https://github.com/hrzlgnm/mex/issues/48)) ([227d3e2](https://github.com/hrzlgnm/mex/commit/227d3e263238c14b9a06ff7717d3d93265e69af4))


### Dependencies

* lock file maintenance ([#51](https://github.com/hrzlgnm/mex/issues/51)) ([280ac60](https://github.com/hrzlgnm/mex/commit/280ac6015e6f6940f91fff23cf702aa333db4898))

## [0.5.0](https://github.com/hrzlgnm/mex/compare/v0.4.2...v0.5.0) (2026-11-10)


### Features

* mouse pane resizing, click focus, and scrollable hex view ([#44](https://github.com/hrzlgnm/mex/issues/44)) ([66fd05b](https://github.com/hrzlgnm/mex/commit/66fd05be5dfbf1b1ce0995935409844e84f144c1))
* scroll focused pane with mouse wheel ([#47](https://github.com/hrzlgnm/mex/issues/47)) ([3ed350a](https://github.com/hrzlgnm/mex/commit/3ed350ae5046300b94c5c8beb02e202eceb7ac18))

## [0.4.2](https://github.com/hrzlgnm/mex/compare/v0.4.1...v0.4.2) (2026-11-10)


### Documentation

* unify tagline, refresh icons and polish README ([#39](https://github.com/hrzlgnm/mex/issues/39)) ([99e5873](https://github.com/hrzlgnm/mex/commit/99e5873041671bce44298af10683ee54f5f5ecb2))

## [0.4.1](https://github.com/hrzlgnm/mex/compare/v0.4.0...v0.4.1) (2026-11-10)


### Tests

* lock enumeration KA/question separation at ingest ([#37](https://github.com/hrzlgnm/mex/issues/37)) ([aef0ec9](https://github.com/hrzlgnm/mex/commit/aef0ec976f0f3047ce87786e288ddd285d8d4566))

## [0.4.0](https://github.com/hrzlgnm/mex/compare/v0.3.1...v0.4.0) (2026-11-10)


### Features

* strip redundant .local suffix from hostnames in left pane ([#35](https://github.com/hrzlgnm/mex/issues/35)) ([b473386](https://github.com/hrzlgnm/mex/commit/b4733869fa68c645db32a7750e177148a2553ca2))
* track enumeration queries in selectable row ([#36](https://github.com/hrzlgnm/mex/issues/36)) ([b1f3ec1](https://github.com/hrzlgnm/mex/commit/b1f3ec1acbd5f1d2478ba6da03245d7a1f5c8c90))


### Documentation

* set up agent skills config for GitHub issue tracker ([#33](https://github.com/hrzlgnm/mex/issues/33)) ([03cb11a](https://github.com/hrzlgnm/mex/commit/03cb11ad3cc541d8bf8024ec281b9985a6196ffa))


### Continuous Integration

* skip release pushes and gate jobs on path-filter ([#32](https://github.com/hrzlgnm/mex/issues/32)) ([1635bcb](https://github.com/hrzlgnm/mex/commit/1635bcbfe42dd611617161833f8cb06c62a73572))

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
