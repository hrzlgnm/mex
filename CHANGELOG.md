# Changelog

## [0.24.0](https://github.com/hrzlgnm/mex/compare/v0.23.0...v0.24.0) (2026-11-26)


### Features

* show each record's DNS section in the Answers pane ([#400](https://github.com/hrzlgnm/mex/issues/400)) ([e708d80](https://github.com/hrzlgnm/mex/commit/e708d80f921210d1800035a9d039337d36590aab))


### Bug Fixes

* replace a service row when only the owner name's case changed ([#403](https://github.com/hrzlgnm/mex/issues/403)) ([9a532fd](https://github.com/hrzlgnm/mex/commit/9a532fdda7917fcf5ef090a6a5f7eb7c817af4ef))

## [0.23.0](https://github.com/hrzlgnm/mex/compare/v0.22.4...v0.23.0) (2026-11-26)


### Features

* send a self question now with r in the Questions pane ([#395](https://github.com/hrzlgnm/mex/issues/395)) ([6136db7](https://github.com/hrzlgnm/mex/commit/6136db7e44c1dc04f6967b2a94bae351eecd040d))


### Code Refactoring

* record own queries with an OwnQuery type that cannot be Observed ([#397](https://github.com/hrzlgnm/mex/issues/397)) ([d83393b](https://github.com/hrzlgnm/mex/commit/d83393b06e2abbac49175d245d2b1fe02ec3da01))


### Tests

* rename gen locals to generation ([#392](https://github.com/hrzlgnm/mex/issues/392)) ([8b787bd](https://github.com/hrzlgnm/mex/commit/8b787bd2c122f42e98a2bdd1c3c7fc4180a318ad))

## [0.22.4](https://github.com/hrzlgnm/mex/compare/v0.22.3...v0.22.4) (2026-11-26)


### Bug Fixes

* keep dotted instance labels when SRV/TXT precede the PTR ([#385](https://github.com/hrzlgnm/mex/issues/385)) ([7ede50e](https://github.com/hrzlgnm/mex/commit/7ede50e3486b7dda4531aef8c22d3ad02e3b786d))
* key names in presentation form so dotted instance labels never collide ([#388](https://github.com/hrzlgnm/mex/issues/388)) ([8b10790](https://github.com/hrzlgnm/mex/commit/8b10790736f67dcaa42532abca42d1bb3ee1d904))
* land late PTRs on their confirmed service, not a pending copy ([#387](https://github.com/hrzlgnm/mex/issues/387)) ([3712661](https://github.com/hrzlgnm/mex/commit/371266171505956141c2c09894d471bfec49dbcb))


### Dependencies

* lock file maintenance ([#391](https://github.com/hrzlgnm/mex/issues/391)) ([fb55141](https://github.com/hrzlgnm/mex/commit/fb55141273ce783da7669cb37b539cc94c48fa20))
* update dependency cargo-auditable to v0.7.8 ([#383](https://github.com/hrzlgnm/mex/issues/383)) ([79ddad5](https://github.com/hrzlgnm/mex/commit/79ddad5312334da2337cadfe7e6d789aff4d777a))
* update dependency sccache to v0.20.1 ([#380](https://github.com/hrzlgnm/mex/issues/380)) ([45896bb](https://github.com/hrzlgnm/mex/commit/45896bbdde3d48368c8229e7d16af4db2874ddd4))
* update rust crate clap to v4.6.10 ([#381](https://github.com/hrzlgnm/mex/issues/381)) ([814b1af](https://github.com/hrzlgnm/mex/commit/814b1afe2495794359ed9808606b1000c861b99c))
* update taiki-e/install-action action to v2.90.10 ([#384](https://github.com/hrzlgnm/mex/issues/384)) ([bf835d0](https://github.com/hrzlgnm/mex/commit/bf835d05d758dcce349358a5c62611e5190dc204))
* update taiki-e/install-action action to v2.90.11 ([#390](https://github.com/hrzlgnm/mex/issues/390)) ([ed79933](https://github.com/hrzlgnm/mex/commit/ed79933f7fd96b20881f9fd0e35f96f227cb0c52))

## [0.22.3](https://github.com/hrzlgnm/mex/compare/v0.22.2...v0.22.3) (2026-11-24)


### Bug Fixes

* build the tests on Windows ([#370](https://github.com/hrzlgnm/mex/issues/370)) ([4932b5d](https://github.com/hrzlgnm/mex/commit/4932b5d789c737899934cc575e4f989ea8c4cda6))
* fold only ASCII letters when comparing names (RFC 6762 §16) ([#377](https://github.com/hrzlgnm/mex/issues/377)) ([2921547](https://github.com/hrzlgnm/mex/commit/2921547f32f56138f04fca8f54cfb61196fdd2c3))
* keep hosts named like a built-in group in their own group ([#375](https://github.com/hrzlgnm/mex/issues/375)) ([2f52a13](https://github.com/hrzlgnm/mex/commit/2f52a132c8c66b8e9fa5b4b5c37c0d1489f17aa1))
* refuse query names over 255 octets ([#364](https://github.com/hrzlgnm/mex/issues/364)) ([ca9352a](https://github.com/hrzlgnm/mex/commit/ca9352a4c93495c9d6e7d95b95de6e5345017367))


### Dependencies

* update anchore/scan-action action to v7.4.3 ([#358](https://github.com/hrzlgnm/mex/issues/358)) ([5f93343](https://github.com/hrzlgnm/mex/commit/5f933437718b55a6a547bc0bbccaded5a38dd004))
* update ghcr.io/hrzlgnm/mdns-browser-arch-aur-builder:v1 docker digest to 9b1f812 ([#360](https://github.com/hrzlgnm/mex/issues/360)) ([7217152](https://github.com/hrzlgnm/mex/commit/72171522f15d2a57503a9b8f374f7d9f2813f2d2))


### Documentation

* names fold ASCII only (RFC 6762 §16) ([#379](https://github.com/hrzlgnm/mex/issues/379)) ([aecee9a](https://github.com/hrzlgnm/mex/commit/aecee9a96e27f234baea4e04b84b39c98a03853e))


### Code Refactoring

* handle codec errors in encoders instead of panicking ([#369](https://github.com/hrzlgnm/mex/issues/369)) ([2b9163a](https://github.com/hrzlgnm/mex/commit/2b9163a91a30d23aa4c5e4e8ce329d7849aa7411))


### Tests

* cover listener error and malformed datagram paths ([#362](https://github.com/hrzlgnm/mex/issues/362)) ([a629280](https://github.com/hrzlgnm/mex/commit/a629280b675d206dec61b7c92d14be1a7005ab70))
* cover remaining anomalies paths ([#373](https://github.com/hrzlgnm/mex/issues/373)) ([1cf1075](https://github.com/hrzlgnm/mex/commit/1cf1075fb98b2b68349b31569c85bfa976f89990))
* cover remaining app paths ([#368](https://github.com/hrzlgnm/mex/issues/368)) ([e8268fe](https://github.com/hrzlgnm/mex/commit/e8268fead1e8f2e1e5fb785d6b59daab671eb790))
* cover remaining browse paths ([#367](https://github.com/hrzlgnm/mex/issues/367)) ([e4b7793](https://github.com/hrzlgnm/mex/commit/e4b779381acf190ccc22087314347d5a8ffaff34))
* cover remaining iface paths ([#366](https://github.com/hrzlgnm/mex/issues/366)) ([9790085](https://github.com/hrzlgnm/mex/commit/9790085b5cb393c2c21dcbf93246728c74bb6ed5))
* cover remaining input paths ([#374](https://github.com/hrzlgnm/mex/issues/374)) ([23080a3](https://github.com/hrzlgnm/mex/commit/23080a397dbf91e0c532ec284bee6ee054d689c0))
* cover remaining schedule paths ([#376](https://github.com/hrzlgnm/mex/issues/376)) ([2ea94fa](https://github.com/hrzlgnm/mex/commit/2ea94fa9e98c62a9bbd99e98656d07ec7370d8ba))
* cover remaining send paths ([#363](https://github.com/hrzlgnm/mex/issues/363)) ([d43e7ed](https://github.com/hrzlgnm/mex/commit/d43e7ed2edb677238291e628c4acf1327e0bf801))
* cover remaining wire paths ([#365](https://github.com/hrzlgnm/mex/issues/365)) ([1621d53](https://github.com/hrzlgnm/mex/commit/1621d536adca364691170f23c11abb05dee0ce09))


### Continuous Integration

* lint the Windows target, tests included ([#371](https://github.com/hrzlgnm/mex/issues/371)) ([98c18d6](https://github.com/hrzlgnm/mex/commit/98c18d66ae04e40a1a6798796f6ae5e83b48f9b4))

## [0.22.2](https://github.com/hrzlgnm/mex/compare/v0.22.1...v0.22.2) (2026-11-23)


### Bug Fixes

* close IPv6 gaps in dump redaction ([#355](https://github.com/hrzlgnm/mex/issues/355)) ([5da20b3](https://github.com/hrzlgnm/mex/commit/5da20b3470f62355c16d283ff416354d1fdada03))
* redact .box URL hosts in dumps ([#356](https://github.com/hrzlgnm/mex/issues/356)) ([99f0993](https://github.com/hrzlgnm/mex/commit/99f09936d5ca8ec26953eb3c86cb69ef5f0f386a))


### Dependencies

* lock file maintenance ([#350](https://github.com/hrzlgnm/mex/issues/350)) ([63fc72e](https://github.com/hrzlgnm/mex/commit/63fc72e450c43abca4bbccca9e3f9954927d32d4))
* update dependency sccache to v0.20.0 ([#352](https://github.com/hrzlgnm/mex/issues/352)) ([19853c9](https://github.com/hrzlgnm/mex/commit/19853c9d109a11531d9df001ffac764c0afadfe5))
* update rust crate anyhow to v1.0.105 ([#351](https://github.com/hrzlgnm/mex/issues/351)) ([13cf43a](https://github.com/hrzlgnm/mex/commit/13cf43a0513fe9685603cceb53d9bb4806a367bb))
* update taiki-e/install-action action to v2.90.8 ([#348](https://github.com/hrzlgnm/mex/issues/348)) ([b61bbf8](https://github.com/hrzlgnm/mex/commit/b61bbf84f467b85aced55b77880385d08e8ccae7))


### Documentation

* agent worktree commands and SSH key for remote git calls ([#357](https://github.com/hrzlgnm/mex/issues/357)) ([45b74f1](https://github.com/hrzlgnm/mex/commit/45b74f19c8cf556b741c9ac9b43afb51173a2c7e))

## [0.22.1](https://github.com/hrzlgnm/mex/compare/v0.22.0...v0.22.1) (2026-11-21)


### Bug Fixes

* **ui:** end the resize glow when a mouse drag is released ([#346](https://github.com/hrzlgnm/mex/issues/346)) ([72e6e05](https://github.com/hrzlgnm/mex/commit/72e6e056bd2ddfbcad07fc2ba1ba9c70c5447d6d))


### Dependencies

* lock file maintenance ([#347](https://github.com/hrzlgnm/mex/issues/347)) ([71c6174](https://github.com/hrzlgnm/mex/commit/71c6174067e5216096d0ecfad5cad77af4d41c07))
* update rust crate url to v2.5.9 ([#342](https://github.com/hrzlgnm/mex/issues/342)) ([2baeab6](https://github.com/hrzlgnm/mex/commit/2baeab6c2b9da4de06cc7285a3db1a9a58268fb1))
* update taiki-e/install-action action to v2.90.7 ([#344](https://github.com/hrzlgnm/mex/issues/344)) ([0205572](https://github.com/hrzlgnm/mex/commit/020557207e3c1643b088761ef1460554f47c1422))

## [0.22.0](https://github.com/hrzlgnm/mex/compare/v0.21.0...v0.22.0) (2026-11-20)


### Features

* **ui:** emphasize the focused pane with a thick border ([#340](https://github.com/hrzlgnm/mex/issues/340)) ([a1838e2](https://github.com/hrzlgnm/mex/commit/a1838e28075043ed28ceaa4fefedab843d9b3388))

## [0.21.0](https://github.com/hrzlgnm/mex/compare/v0.20.5...v0.21.0) (2026-11-20)


### Features

* show rusage and memory in diagnostics ([#338](https://github.com/hrzlgnm/mex/issues/338)) ([3020ad7](https://github.com/hrzlgnm/mex/commit/3020ad76380c3adf510b1c346a57894bfe099621))


### Dependencies

* lock file maintenance ([#339](https://github.com/hrzlgnm/mex/issues/339)) ([b07adbb](https://github.com/hrzlgnm/mex/commit/b07adbb5cf9e9d1711df63f74c4de77b27014654))
* update rust crate clap to v4.6.9 ([#333](https://github.com/hrzlgnm/mex/issues/333)) ([07d9c16](https://github.com/hrzlgnm/mex/commit/07d9c16f7ec90508b009c1eec2f7a0b2d252a9a9))


### Continuous Integration

* add Codecov test coverage badge to README ([#336](https://github.com/hrzlgnm/mex/issues/336)) ([39939d2](https://github.com/hrzlgnm/mex/commit/39939d29b2819c0245ff453ceef6949955e0fd13))

## [0.20.5](https://github.com/hrzlgnm/mex/compare/v0.20.4...v0.20.5) (2026-11-19)


### Dependencies

* lock file maintenance ([#332](https://github.com/hrzlgnm/mex/issues/332)) ([354c836](https://github.com/hrzlgnm/mex/commit/354c8362a114fa95120bd44ffaf22b10a32bf5b7))
* update taiki-e/install-action action to v2.90.6 ([#327](https://github.com/hrzlgnm/mex/issues/327)) ([4eb8e27](https://github.com/hrzlgnm/mex/commit/4eb8e27c0818eff7e2477c1afb0c7fc9b207341e))


### Code Refactoring

* rename metrics to diagnostics ([#331](https://github.com/hrzlgnm/mex/issues/331)) ([5fc3ea8](https://github.com/hrzlgnm/mex/commit/5fc3ea8bb92cec749fe9b58506d5f0da9ba06af7))


### Tests

* raise files below 90% line coverage ([#328](https://github.com/hrzlgnm/mex/issues/328)) ([888a359](https://github.com/hrzlgnm/mex/commit/888a3594b1425bfe2ca831ec1380c2724f339fd8))


### Continuous Integration

* report test coverage on every code change ([#324](https://github.com/hrzlgnm/mex/issues/324)) ([b670426](https://github.com/hrzlgnm/mex/commit/b670426c63f75fd3789e48e81a32240ac44d968f))

## [0.20.4](https://github.com/hrzlgnm/mex/compare/v0.20.3...v0.20.4) (2026-11-19)


### Bug Fixes

* stop the listener when the app drops its query sender ([#321](https://github.com/hrzlgnm/mex/issues/321)) ([e41579a](https://github.com/hrzlgnm/mex/commit/e41579ab302c3fb372c6d728012c5a121215050a))

## [0.20.3](https://github.com/hrzlgnm/mex/compare/v0.20.2...v0.20.3) (2026-11-18)


### Bug Fixes

* cap the per-source packet counters ([#314](https://github.com/hrzlgnm/mex/issues/314)) ([01350f1](https://github.com/hrzlgnm/mex/commit/01350f13d87fe13678de989ca6491c8143a3460d))
* dedup Questions rows by name case-insensitively ([#310](https://github.com/hrzlgnm/mex/issues/310)) ([03ec56a](https://github.com/hrzlgnm/mex/commit/03ec56a341230fdd66e15884fa1fdc18319ea991))
* don't overflow the half-TTL known-answer check on huge TTLs ([#308](https://github.com/hrzlgnm/mex/issues/308)) ([3db7178](https://github.com/hrzlgnm/mex/commit/3db717848b528b248161692f360a5fcbcf4556df))
* keep the selection on Home/End in an empty pane ([#309](https://github.com/hrzlgnm/mex/issues/309)) ([27a440b](https://github.com/hrzlgnm/mex/commit/27a440b897d3f693eec13bc0a67427a8f1b89f9d))
* let pending instances' unique answers dampen discovery ([#313](https://github.com/hrzlgnm/mex/issues/313)) ([4071a36](https://github.com/hrzlgnm/mex/commit/4071a3608410f956e2ce785d821f2143e90e6da7))
* refresh pending instances' rows at 80% of their TTL ([#317](https://github.com/hrzlgnm/mex/issues/317)) ([32364a7](https://github.com/hrzlgnm/mex/commit/32364a7a93abb19e1658678dc8fc99a2e3d6acdb))


### Dependencies

* lock file maintenance ([#311](https://github.com/hrzlgnm/mex/issues/311)) ([752e6f6](https://github.com/hrzlgnm/mex/commit/752e6f6c04cfd7441680ff02c275e7b2e1368bee))
* update hrzlgnm/actions action to v2.15.0 ([#312](https://github.com/hrzlgnm/mex/issues/312)) ([6c555c7](https://github.com/hrzlgnm/mex/commit/6c555c71ab530387c37a82ee2d281f794de8ba82))


### Documentation

* describe the logger's default log file correctly ([#318](https://github.com/hrzlgnm/mex/issues/318)) ([386b8d7](https://github.com/hrzlgnm/mex/commit/386b8d759e85d89a2cd8e28e41b22d2832442c0c))


### Code Refactoring

* collect draw-measured state in app::Layout ([#290](https://github.com/hrzlgnm/mex/issues/290)) ([ca195d4](https://github.com/hrzlgnm/mex/commit/ca195d45c1d05aff23dd6e7f82001bfdeab91630))
* collect focus, selection and splits in app::ViewState ([#291](https://github.com/hrzlgnm/mex/issues/291)) ([eb99dd7](https://github.com/hrzlgnm/mex/commit/eb99dd783b437abcc6f1ec7d7c1bacf483c50018))
* give NSEC address denials their own type ([#295](https://github.com/hrzlgnm/mex/issues/295)) ([8b987d2](https://github.com/hrzlgnm/mex/commit/8b987d2507174ee5398f3d396fb008bf25ac495e))
* make the remaining App fields private ([#292](https://github.com/hrzlgnm/mex/issues/292)) ([c733f7d](https://github.com/hrzlgnm/mex/commit/c733f7d053e271f8c927cf032fb9998c953d8401))
* move ENUM_SERVICE to browse to break the anomalies-app cycle ([#289](https://github.com/hrzlgnm/mex/issues/289)) ([0bbf729](https://github.com/hrzlgnm/mex/commit/0bbf729382644df22cea22193f691e1b595e6211))
* move scheduling state into app::Scheduler ([#296](https://github.com/hrzlgnm/mex/issues/296)) ([0900054](https://github.com/hrzlgnm/mex/commit/09000541a4656db6af056d4a16a3d026a8ce3dec))
* move the cache-independent scheduling rules onto Scheduler ([#298](https://github.com/hrzlgnm/mex/issues/298)) ([84cd573](https://github.com/hrzlgnm/mex/commit/84cd57351a37a174613cd9ebfbf766b1c3a98751))
* move the logger out of main into its own module ([#284](https://github.com/hrzlgnm/mex/issues/284)) ([963ab33](https://github.com/hrzlgnm/mex/commit/963ab3392fc0f78a3afb893137bc12c8932a2408))
* split anomalies into records, resolve, naming, questions and scope modules ([#282](https://github.com/hrzlgnm/mex/issues/282)) ([d3cd54a](https://github.com/hrzlgnm/mex/commit/d3cd54a38bc3ea07d8254fb4e1e8b5957256aa9c))
* split App methods into child modules by job ([#280](https://github.com/hrzlgnm/mex/issues/280)) ([ba959a0](https://github.com/hrzlgnm/mex/commit/ba959a0ef902bfede3d0c2e612e570a4a9220958))
* split app tests into topic modules ([#279](https://github.com/hrzlgnm/mex/issues/279)) ([87f3b05](https://github.com/hrzlgnm/mex/commit/87f3b05a4b14451d5ef84629a33a404d47ff1887))
* split browse into iface, listener, send and wire modules ([#281](https://github.com/hrzlgnm/mex/issues/281)) ([ebe8e0e](https://github.com/hrzlgnm/mex/commit/ebe8e0ef4ad6d8701d91adb1ee8bb11aca7b9a37))
* split ui into per-pane modules ([#283](https://github.com/hrzlgnm/mex/issues/283)) ([e3edd76](https://github.com/hrzlgnm/mex/commit/e3edd76b04cc93ebd0f91614484bc86d1fa80d10))


### Tests

* let service_of prefer a full-key match over a bare instance ([#319](https://github.com/hrzlgnm/mex/issues/319)) ([3d9ddb3](https://github.com/hrzlgnm/mex/commit/3d9ddb3db8e6f0e6a4858f98358dc9db6da14f00))
* match row helpers on the full instance name and real liveness ([#315](https://github.com/hrzlgnm/mex/issues/315)) ([264efef](https://github.com/hrzlgnm/mex/commit/264efef672abe8b8b199d7ccd4f7a2ce3ecf6411))
* merge duplicate row helpers and file [#255](https://github.com/hrzlgnm/mex/issues/255) tests under denials ([#302](https://github.com/hrzlgnm/mex/issues/302)) ([79c22c7](https://github.com/hrzlgnm/mex/commit/79c22c79426ebc8d0bac52213507aa4b664954eb))
* move the logger tests next to the logger ([#299](https://github.com/hrzlgnm/mex/issues/299)) ([63b7714](https://github.com/hrzlgnm/mex/commit/63b7714e5a8c41bf6c1eeb0d0a5647dbbbbf2904))
* split anomalies tests into topic modules ([#300](https://github.com/hrzlgnm/mex/issues/300)) ([f4cf54b](https://github.com/hrzlgnm/mex/commit/f4cf54b150313f0422b30356bd66df65abe916aa))
* split browse tests into topic modules ([#301](https://github.com/hrzlgnm/mex/issues/301)) ([2cf38ea](https://github.com/hrzlgnm/mex/commit/2cf38ea63a77269ee1d8c5c6e48e079ca3355e56))


### Continuous Integration

* check macOS with clippy on Linux instead of a PR macOS build ([#288](https://github.com/hrzlgnm/mex/issues/288)) ([5977d49](https://github.com/hrzlgnm/mex/commit/5977d495e2576eddf85c37fde1a7edbf1c019bc7))
* check SPDX headers with the shared reusable workflow ([#320](https://github.com/hrzlgnm/mex/issues/320)) ([12bcad7](https://github.com/hrzlgnm/mex/commit/12bcad7b94d8a5b473d1e399a4579b758a67ef6a))
* fail when a source or config file lacks its SPDX header ([#305](https://github.com/hrzlgnm/mex/issues/305)) ([a30c09d](https://github.com/hrzlgnm/mex/commit/a30c09dd9f0afbab46633ceb7e6754ab51a71571))
* require the SPDX identifier in a file's header or footer ([#307](https://github.com/hrzlgnm/mex/issues/307)) ([2904a35](https://github.com/hrzlgnm/mex/commit/2904a35e870da2e4479b4ad825bb6b37c102d416))
* trim PR builds to one target per OS family and skip the unchanged-deps SBOM ([#287](https://github.com/hrzlgnm/mex/issues/287)) ([0376ddc](https://github.com/hrzlgnm/mex/commit/0376ddc9cd2ccd40b69582154024abde74cef6c0))

## [0.20.2](https://github.com/hrzlgnm/mex/compare/v0.20.1...v0.20.2) (2026-11-17)


### Bug Fixes

* show record findings under every announcing source ([#275](https://github.com/hrzlgnm/mex/issues/275)) ([86dc930](https://github.com/hrzlgnm/mex/commit/86dc930d70765720f323b13dd349d800d4cd1a80))

## [0.20.1](https://github.com/hrzlgnm/mex/compare/v0.20.0...v0.20.1) (2026-11-17)


### Bug Fixes

* count a multi-homed host's per-NIC answers as one responder ([#273](https://github.com/hrzlgnm/mex/issues/273)) ([c8e1ef1](https://github.com/hrzlgnm/mex/commit/c8e1ef1ea721d1f47848b048398d91dffed6ade6))
* show goodbye TTL cells in dark gray instead of red ([#272](https://github.com/hrzlgnm/mex/issues/272)) ([e482b24](https://github.com/hrzlgnm/mex/commit/e482b248c4185e804bca7b37f0f406d6825f1dc5))

## [0.20.0](https://github.com/hrzlgnm/mex/compare/v0.19.0...v0.20.0) (2026-11-17)


### Features

* age out Questions rows by a time window ([#269](https://github.com/hrzlgnm/mex/issues/269)) ([3bcc7ec](https://github.com/hrzlgnm/mex/commit/3bcc7ec7cf656de3966e0735d16c6e368a349cd6))
* flag conflicting address answers ([#263](https://github.com/hrzlgnm/mex/issues/263)) ([5954689](https://github.com/hrzlgnm/mex/commit/5954689847f9f7fd4fa505b27df320cad760bd12))
* hide address rows a service's responder denies via NSEC ([#255](https://github.com/hrzlgnm/mex/issues/255)) ([d8646ce](https://github.com/hrzlgnm/mex/commit/d8646ceb9954ecff2b76b589ad763c60505a47c3))
* name the device behind a source address ([#262](https://github.com/hrzlgnm/mex/issues/262)) ([0657ed8](https://github.com/hrzlgnm/mex/commit/0657ed8454e8a8337bcf53e4e5dd1c7b0b3c4933))
* show anomalies next to their owner ([#259](https://github.com/hrzlgnm/mex/issues/259)) ([43e31a6](https://github.com/hrzlgnm/mex/commit/43e31a6e2e40af31cef63b5ce10f06950bd83855))


### Bug Fixes

* keep per-link copies of a record from one source ([#265](https://github.com/hrzlgnm/mex/issues/265)) ([e46601c](https://github.com/hrzlgnm/mex/commit/e46601c65ea3adc1381f366d2bd0aa74d0eaf84a))


### Dependencies

* lock file maintenance ([#268](https://github.com/hrzlgnm/mex/issues/268)) ([7d13ac2](https://github.com/hrzlgnm/mex/commit/7d13ac2959703663efa08767a014c227314c7e84))
* update rust crate clap to v4.6.8 ([#258](https://github.com/hrzlgnm/mex/issues/258)) ([6a4a59d](https://github.com/hrzlgnm/mex/commit/6a4a59d3eb4d7382d0ec1c80c8c918921a85e3a7))


### Code Refactoring

* drop finding rows from the metrics overlay ([#261](https://github.com/hrzlgnm/mex/issues/261)) ([b269431](https://github.com/hrzlgnm/mex/commit/b269431f2b89a2e933a06e0fee75f5607c02b0c0))
* drop the repeated source and icon from finding rows ([#267](https://github.com/hrzlgnm/mex/issues/267)) ([ded3276](https://github.com/hrzlgnm/mex/commit/ded32766d46f8175956cf1a96e8a92ee61076360))
* remove the Anomalies pane ([#260](https://github.com/hrzlgnm/mex/issues/260)) ([6dfc462](https://github.com/hrzlgnm/mex/commit/6dfc4628f4cabfdf97879f93b77fddcdf1b4cb8e))

## [0.19.0](https://github.com/hrzlgnm/mex/compare/v0.18.3...v0.19.0) (2026-11-16)


### Features

* hold query schedules while no family can transmit ([#254](https://github.com/hrzlgnm/mex/issues/254)) ([88b3991](https://github.com/hrzlgnm/mex/commit/88b39916103cfeee7c4c8b65f1360cd85a3d8a26))
* show out-of-scope mDNS types only as anomalies ([#244](https://github.com/hrzlgnm/mex/issues/244)) ([24dbc3f](https://github.com/hrzlgnm/mex/commit/24dbc3fcecfa061a2a1377d2151725f14e9d2070))


### Bug Fixes

* enable multicast loop so local responders hear our queries ([#256](https://github.com/hrzlgnm/mex/issues/256)) ([3d9c01b](https://github.com/hrzlgnm/mex/commit/3d9c01b4476970b3c2b02b57bb03ee220a74a7ff))
* log query send and egress pin failures ([#251](https://github.com/hrzlgnm/mex/issues/251)) ([ba1281a](https://github.com/hrzlgnm/mex/commit/ba1281ae151cbd39cd70f0ecee688d0db31b878f))
* send nothing when a family has no usable interface ([#252](https://github.com/hrzlgnm/mex/issues/252)) ([fd661ff](https://github.com/hrzlgnm/mex/commit/fd661ffb97605223e2344b5acb75d233d812ed06))


### Dependencies

* update rust crate simple-dns to v0.13.1 ([#242](https://github.com/hrzlgnm/mex/issues/242)) ([bed537e](https://github.com/hrzlgnm/mex/commit/bed537e5689613b085dec3e473d77b989626ad61))


### Code Refactoring

* drive both mDNS sockets from one mio poll loop ([#250](https://github.com/hrzlgnm/mex/issues/250)) ([773ddd3](https://github.com/hrzlgnm/mex/commit/773ddd37415e6e12175cdf8f585d67962b57048d))

## [0.18.3](https://github.com/hrzlgnm/mex/compare/v0.18.2...v0.18.3) (2026-11-15)


### Bug Fixes

* refresh each cached row on its own TTL, once ([#236](https://github.com/hrzlgnm/mex/issues/236)) ([4808fd3](https://github.com/hrzlgnm/mex/commit/4808fd3578f967f1fe095849984a03881fa4664e))

## [0.18.2](https://github.com/hrzlgnm/mex/compare/v0.18.1...v0.18.2) (2026-11-15)


### Code Refactoring

* derive the program name from CARGO_PKG_NAME ([#233](https://github.com/hrzlgnm/mex/issues/233)) ([fb75373](https://github.com/hrzlgnm/mex/commit/fb7537367ab8ebd8a680bc104ad272d09d9cea03))
* render Questions DUE labels from TimerKind ([#232](https://github.com/hrzlgnm/mex/issues/232)) ([6a21a6c](https://github.com/hrzlgnm/mex/commit/6a21a6c34fc7ca42edfc58bb292aa7f04394f095))

## [0.18.1](https://github.com/hrzlgnm/mex/compare/v0.18.0...v0.18.1) (2026-11-15)


### Bug Fixes

* label own questions as self in the state dump ([#225](https://github.com/hrzlgnm/mex/issues/225)) ([b88424a](https://github.com/hrzlgnm/mex/commit/b88424a7e6da52754de873a124dbab34df2d00a4))
* share one .local suffix helper, removing a UI panic ([#228](https://github.com/hrzlgnm/mex/issues/228)) ([0fa538a](https://github.com/hrzlgnm/mex/commit/0fa538a6aca8198b8ea547b47b82b33edd428072))


### Documentation

* trim the known-limitations section ([#223](https://github.com/hrzlgnm/mex/issues/223)) ([10b1fb0](https://github.com/hrzlgnm/mex/commit/10b1fb0b5ba1688669a2dc5bcef6df0c834b0768))


### Code Refactoring

* derive record type names from one shared table ([#227](https://github.com/hrzlgnm/mex/issues/227)) ([b9c601c](https://github.com/hrzlgnm/mex/commit/b9c601cd64c7b48fa1af570501e3d7e9b990453e))
* share DNS-SD protocol and subtype label checks ([#229](https://github.com/hrzlgnm/mex/issues/229)) ([9d7dbfc](https://github.com/hrzlgnm/mex/commit/9d7dbfc2e8e73629079d32732efe788594a2a2cb))
* share the DNS-SD enumeration name with anomaly checks ([#226](https://github.com/hrzlgnm/mex/issues/226)) ([0df8ddc](https://github.com/hrzlgnm/mex/commit/0df8ddc945658a19801dcae8ccdcfafa178a63dc))

## [0.18.0](https://github.com/hrzlgnm/mex/compare/v0.17.2...v0.18.0) (2026-11-15)


### Features

* rework unicast-leak into unicast-style-response ([#220](https://github.com/hrzlgnm/mex/issues/220)) ([a5df25c](https://github.com/hrzlgnm/mex/commit/a5df25c322f3e15610f21d77a853e8bebb3ee396))


### Bug Fixes

* flag missing flush bit in unicast replies to port 5353 ([#219](https://github.com/hrzlgnm/mex/issues/219)) ([912dc31](https://github.com/hrzlgnm/mex/commit/912dc314c901d545258c2199be0674fed8efce1e))
* list each question finding once in global anomaly views ([#217](https://github.com/hrzlgnm/mex/issues/217)) ([a5d9874](https://github.com/hrzlgnm/mex/commit/a5d98746dd9cf0e436755dfc0f8699c461695c6c))
* report NS/SOA outside mDNS domains as info, not an error ([#218](https://github.com/hrzlgnm/mex/issues/218)) ([56ac85d](https://github.com/hrzlgnm/mex/commit/56ac85d076aa553c5d087f4ca33e4ad11675beee))


### Dependencies

* update dtolnay/rust-toolchain digest to 3900882 ([#214](https://github.com/hrzlgnm/mex/issues/214)) ([6057667](https://github.com/hrzlgnm/mex/commit/6057667aa052e0e688ed3184ec880e4cc5186325))
* update ghcr.io/hrzlgnm/mdns-browser-arch-aur-builder:v1 docker digest to 09fea71 ([#215](https://github.com/hrzlgnm/mex/issues/215)) ([ee76b0f](https://github.com/hrzlgnm/mex/commit/ee76b0f00058fefab6092a28fccb1604b3138199))


### Code Refactoring

* drop the global-question anomaly ([#222](https://github.com/hrzlgnm/mex/issues/222)) ([90b0e24](https://github.com/hrzlgnm/mex/commit/90b0e242d8d016b0207531df46859f8643f4f39d))

## [0.17.2](https://github.com/hrzlgnm/mex/compare/v0.17.1...v0.17.2) (2026-11-15)


### Bug Fixes

* show own questions with a trailing root dot like observed ones ([#212](https://github.com/hrzlgnm/mex/issues/212)) ([650efed](https://github.com/hrzlgnm/mex/commit/650efedeb664d0918b6fecaba75eb3310467fa48))

## [0.17.1](https://github.com/hrzlgnm/mex/compare/v0.17.0...v0.17.1) (2026-11-14)


### Bug Fixes

* show dampened A/AAAA interests as pending in the Questions pane ([#210](https://github.com/hrzlgnm/mex/issues/210)) ([e3fcba5](https://github.com/hrzlgnm/mex/commit/e3fcba5ef66ffaebcdd1b0cea068db0f48a96591))

## [0.17.0](https://github.com/hrzlgnm/mex/compare/v0.16.2...v0.17.0) (2026-11-14)


### Features

* flag non-.local names queried over mDNS ([#197](https://github.com/hrzlgnm/mex/issues/197)) ([9a5209e](https://github.com/hrzlgnm/mex/commit/9a5209e01263190bfc3ccfa6192819fa172a05a3))


### Bug Fixes

* accept "." SRV target, reverse-PTR TTL base, measure TXT on the wire ([#195](https://github.com/hrzlgnm/mex/issues/195)) ([2c23340](https://github.com/hrzlgnm/mex/commit/2c23340bd49f9997ad19c20534b6c1afc9143f4b))
* avoid u32 overflow in 80%-TTL refresh window checks ([#202](https://github.com/hrzlgnm/mex/issues/202)) ([7ca6623](https://github.com/hrzlgnm/mex/commit/7ca662308cc3d29b4f51f316e933976a8486916f))
* correct anomaly RFC citations and requirement levels ([#192](https://github.com/hrzlgnm/mex/issues/192)) ([f4f0d04](https://github.com/hrzlgnm/mex/commit/f4f0d041f244477dab78aeb6af8cdc0470cd4e5e))
* silently ignore mDNS responses with non-zero RCODE ([#194](https://github.com/hrzlgnm/mex/issues/194)) ([b02fbac](https://github.com/hrzlgnm/mex/commit/b02fbace6fa7847cbf45cd2092cb9fe1aec1f62d))
* skip first query when a unique answer is already cached ([#201](https://github.com/hrzlgnm/mex/issues/201)) ([696a1aa](https://github.com/hrzlgnm/mex/commit/696a1aa05f2db784b06b61f0e4589c8a95f710ae))
* stop flagging RFC-compliant mDNS questions and MX ([#193](https://github.com/hrzlgnm/mex/issues/193)) ([3ccfd5c](https://github.com/hrzlgnm/mex/commit/3ccfd5c18017bcfc1b2b5bef60e74475fd8ba99b))


### Performance Improvements

* re-clamp cursors only when selection state changed ([#207](https://github.com/hrzlgnm/mex/issues/207)) ([3d7cd46](https://github.com/hrzlgnm/mex/commit/3d7cd465f30aa8ee22e6233530cd8fd0ea82128c))
* redraw the TUI only when something changed ([#206](https://github.com/hrzlgnm/mex/issues/206)) ([b27ea42](https://github.com/hrzlgnm/mex/commit/b27ea42f5cac21d882285ba35550ed8c9c2706d2))
* run the anomaly analyzer once per frame ([#205](https://github.com/hrzlgnm/mex/issues/205)) ([36d873f](https://github.com/hrzlgnm/mex/commit/36d873f4ab6d31f32905b4ed2541f4c3d362e18b))
* sort detail rows by SocketAddr instead of formatted strings ([#204](https://github.com/hrzlgnm/mex/issues/204)) ([6f300e9](https://github.com/hrzlgnm/mex/commit/6f300e9fde40af98383703fe142bf44834bf5874))


### Dependencies

* update rust crate nix to 0.32 ([#200](https://github.com/hrzlgnm/mex/issues/200)) ([ea89341](https://github.com/hrzlgnm/mex/commit/ea89341a8d12c1b49231883914680bbb3cf6a8ee))


### Documentation

* agents to claude ([#198](https://github.com/hrzlgnm/mex/issues/198)) ([9ca7b9f](https://github.com/hrzlgnm/mex/commit/9ca7b9f2b90736f8c6cbb22648a821b35b12d68b))

## [0.16.2](https://github.com/hrzlgnm/mex/compare/v0.16.1...v0.16.2) (2026-11-14)


### Bug Fixes

* encode name and version into dump file name ([#190](https://github.com/hrzlgnm/mex/issues/190)) ([4d76ea0](https://github.com/hrzlgnm/mex/commit/4d76ea0e83aba62dc5bda97421d75423e12f0c3b))

## [0.16.1](https://github.com/hrzlgnm/mex/compare/v0.16.0...v0.16.1) (2026-11-14)


### Bug Fixes

* accept arbitrary RFC 6763 subtype identifiers ([#186](https://github.com/hrzlgnm/mex/issues/186)) ([f80fddb](https://github.com/hrzlgnm/mex/commit/f80fddb5dd0ae5b39345a5c84787034aef378000))
* distinguish mDNS address outcomes ([#189](https://github.com/hrzlgnm/mex/issues/189)) ([f1b0fc0](https://github.com/hrzlgnm/mex/commit/f1b0fc0fbc0d70e906cee58de86be03957e1f80d))

## [0.16.0](https://github.com/hrzlgnm/mex/compare/v0.15.2...v0.16.0) (2026-11-14)


### Features

* add clickable question fields to the Hex pane ([#183](https://github.com/hrzlgnm/mex/issues/183)) ([66cb178](https://github.com/hrzlgnm/mex/commit/66cb178653f3575173e25652e998def3c9e588bb))
* add clickable record fields to Hex pane ([#181](https://github.com/hrzlgnm/mex/issues/181)) ([569c4c9](https://github.com/hrzlgnm/mex/commit/569c4c9d9ed7d9b4b376d22248a83b7eb8167ff3))


### Documentation

* add Copilot instructions pointing to AGENTS.md ([#184](https://github.com/hrzlgnm/mex/issues/184)) ([183f65e](https://github.com/hrzlgnm/mex/commit/183f65e3897cd7a4ce3d66b2811c4da59adc2ce7))

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
