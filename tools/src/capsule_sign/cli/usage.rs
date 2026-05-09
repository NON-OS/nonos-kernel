// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

pub const TOP: &str = "\
capsule-sign — NØNOS host trust-chain toolchain (v3)

  keygen          --alg <ed25519|mldsa65> --out <prefix>
  derive-id       --handle <s> --domain <s> [--recovery <s>]
  mk-trust-policy --epoch <n> --ta-pub <alg=path> [--ta-pub <alg=path>] --out <path>
  sign-id-cert    --serial <n> --nonos-id <hex32> --ns-glob <s> [--ns-glob <s>]
                  --caps-ceiling <hex64> --epoch <n>
                  --valid-from-ms <n> --valid-until-ms <n>
                  --pub-key <alg=path> [--pub-key <alg=path>]
                  --ta-seed <alg=path> [--ta-seed <alg=path>]
                  [--metadata <s>] --out <path>
  sign-manifest   --cert <path> --namespace <s> --version <maj.min.patch>
                  --target <triple> --elf <path>
                  --required-caps <hex64> --optional-caps <hex64>
                  [--endpoint <kind:port:name>]
                  --pub-seed <alg=path> [--pub-seed <alg=path>] --out <path>

Seeds and pubkeys live on local disk for v1; production-key-storage
(HSM, ceremony) is the next slice. Files are NONOSSK1/NONOSPK1
self-tagged binary blobs written by `keygen`.";
