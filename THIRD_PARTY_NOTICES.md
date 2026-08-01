# Third-Party Notices

This source distribution includes third-party source and data. The project
`LICENSE-ISC` applies only to project-authored material and does not supersede
the terms below. Source headers and the referenced license files remain
authoritative. These notices address source distribution; they do not by
themselves establish compliance for every possible linked binary.

## Goosig and mini-gmp

The native Goosig subset is in [`vendor/goosig/`](vendor/goosig/) and is
wrapped by [`crates/hns-goosig/`](crates/hns-goosig/). The retained files are
byte-identical to their counterparts in the locally locked `goosig` 0.11.0
npm release (integrity
`sha512-Bk3gMuk1odsF3+Z7Ir9KZwRHfbisIYxqShh4eMW1fKkVhP1MGG7b0bn1FK9SmFZkQrqvYVr4dbV5+TZwNTQfyQ==`),
whose metadata identifies [handshake-org/goosig](https://github.com/handshake-org/goosig).
Neither retained repository history nor the local package metadata proves the
exact upstream Git commit behind that release, so that commit remains
unresolved.

The complete retained Goosig notice is
[`vendor/goosig/LICENSE`](vendor/goosig/LICENSE). It records:

- MIT terms and copyright (c) 2018 Christopher Jeffrey;
- Apache-2.0 portions based on `kwantam/libGooPy`, copyright (c) 2018
  Dan Boneh and Riad S. Wahby;
- BSD-3-Clause portions based on `golang/go`, copyright (c) 2009 The Go
  Authors; and
- MIT portions based on `indutny/miller-rabin`, copyright (c) 2014 Fedor
  Indutny.

The complete Apache License 2.0 text is in
[`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).

The bundled GNU MP Library mini-gmp sources are
[`mini-gmp.c`](vendor/goosig/src/goo/mini-gmp.c) and
[`mini-gmp.h`](vendor/goosig/src/goo/mini-gmp.h). Their file-specific headers
take precedence over the broader Goosig notice, identify the Free Software
Foundation copyrights, and offer
`LGPL-3.0-or-later OR GPL-2.0-or-later` (or both in parallel). This source
distribution elects the LGPL-3.0-or-later option.
Complete LGPL v3 and GPL v3 texts are in
[`LICENSES/LGPL-3.0-or-later.txt`](LICENSES/LGPL-3.0-or-later.txt) and
[`LICENSES/GPL-3.0-or-later.txt`](LICENSES/GPL-3.0-or-later.txt). GPL v3 is
included because LGPL v3 supplements GPL v3 and is also a permitted later
version under the source headers' GPL-2.0-or-later alternative. That GPL
alternative remains available; selecting LGPL-3.0-or-later here does not
remove it.

## Vendored secp256k1

The source is in [`vendor/secp256k1/`](vendor/secp256k1/) and is wrapped by
[`crates/hns-secp256k1/`](crates/hns-secp256k1/). The complete retained tree
is byte-identical to `deps/secp256k1` in the locally locked `bcrypto` 5.5.2
npm release (integrity
`sha512-k3PF755oJM0+25iOVuraNedF5XneykxRwl+oBoMeQPfYee4qX8hHQhKCsNZWLthNYgi41GH2ysopd/8sDQDhEw==`).
The exact standalone secp256k1 upstream Git commit is not established by the
retained repository or local package metadata and remains unresolved.

License: MIT. Copyright (c) 2013 Pieter Wuille. The complete notice is
[`vendor/secp256k1/COPYING`](vendor/secp256k1/COPYING); individual retained
files also preserve their own copyright and provenance headers, including
bcrypto-originated build material.

## Embedded HSD name-policy databases

The embedded files are
[`crates/hns-consensus/vendor/names.db`](crates/hns-consensus/vendor/names.db)
and
[`crates/hns-consensus/vendor/lockup.db`](crates/hns-consensus/vendor/lockup.db).
They are byte-identical to `lib/covenants/names.db` and
`lib/covenants/lockup.db` in the locally installed HSD 8.99.0 package.
Separately, repository evidence in
[`fixtures/hsd/name-states/name-policy-v1.json`](fixtures/hsd/name-states/name-policy-v1.json)
identifies [handshake-org/hsd](https://github.com/handshake-org/hsd) revision
`698e252ebc7b5c1dd0a9587e342fdd153d020ae4` as its oracle and records these
BLAKE2b-256 values:

- `names.db`:
  `7e1e7fe4f51704c8f11a576840d1049b213d54073534a4dd8d73ab6ff727b5d1`
  (SHA-256
  `e7090c9348b6be2b87801b91dbae78d33c2c3916794e831d60cc4b367c2b965e`);
- `lockup.db`:
  `a733b96a2e652fc2e839776f4b7e497371e7bb53f831b5fca9b4b42e014d1780`
  (SHA-256
  `a7af1e93afa223b43f0d115814e001fc9312e58160c57e59662362c28aaefe3b`).

The installed HSD package contains no `gitHead` metadata, so the exact Git
commit from which these embedded copies were extracted is not independently
established beyond that fixture record.

The [`fixtures/hsd/`](fixtures/hsd/) tree contains project-generated oracle
vectors plus retained or transformed material from the pinned HSD corpus. To
the extent any fixture incorporates HSD material, that material remains under
the HSD MIT terms reproduced below; the project ISC grant does not replace
those terms.

The HSD package metadata declares MIT and supplies the following complete
license notice. The binary databases contain no internal license metadata,
and the retained local evidence does not establish a separate license or
pre-HSD provenance for their underlying source datasets; those narrower
questions remain unresolved.

This software is licensed under the MIT License.

Copyright (c) 2014-2015, Fedor Indutny (https://github.com/indutny)
Copyright (c) 2014-2018, Christopher Jeffrey (https://github.com/chjj)
Copyright (c) 2014-2018, Bcoin Contributors (https://github.com/bcoin-org)
Copyright (c) 2018, Handshake Contributors (https://github.com/handshake-org)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
