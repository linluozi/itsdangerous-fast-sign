# NOTICE — modified work

This repository is a **modified copy** of
[itsdangerous](https://github.com/pallets/itsdangerous), copyright 2011 Pallets,
distributed under the BSD-3-Clause licence (see `LICENSE.txt`, unmodified).

## Upstream source

| | |
|---|---|
| Repository | https://github.com/pallets/itsdangerous |
| Commit | `672971d6a2ef9f85151e53283113f33d642dabd` (`main`, 2025-06-14) |
| Version string | `2.3.0.dev` |
| Licence | BSD-3-Clause |

Every file outside the list below is **byte-for-byte identical** to that commit
(the test suite, documentation, examples, packaging metadata and licence).

## Modified files

| File | Change |
|---|---|
| `src/itsdangerous/signer.py` | HMAC computed without the Python `HMAC` wrapper; derived signing key memoised per signer; `_resolve_digest_method()` / `_pad_key()` helpers |
| `src/itsdangerous/serializer.py` | `make_signer()` and `iter_unsigners()` reuse signer instances per configuration |
| `src/itsdangerous/encoding.py` | `base64_decode()` decodes in one pass (`translate` + `a2b_base64`) |
| `src/itsdangerous/url_safe.py` | `dump_payload()` skips a zlib attempt that provably cannot save a byte |

## Added files

| File | Purpose |
|---|---|
| `tests/test_differential.py` | Compares this build against an upstream checkout, output by output |
| `bench/` | A/B, A/A, ablation, call-count and gate-proof harnesses + raw results |
| `assets/` | Figures used by the README, generated from `bench/results/` |
| `NOTICE.md`, `Makefile`, `requirements-dev.txt`, `pyproject.toml` additions | This notice, local tasks, dev/test dependencies |

`docs/upstream_README.md` is the upstream project's original README, kept for
reference; the top-level `README.md` documents this build.

## Nature of the modification

The changes remove interpreter overhead; they do not alter the token format, the
public API, the exception types or the cryptographic construction. HMAC is
computed exactly as `hmac.HMAC` computes it (ipad/opad padding, two digests);
key derivation, zlib thresholds and base64 decoding produce the same bytes as
before. `tests/test_differential.py` and `bench/measure_gate.py` verify this
against the upstream commit above.

## Trademark / attribution

"itsdangerous" and "Pallets" are used only to identify the origin of this
derivative work. This build is not an official Pallets release; please report
issues with it here, not to the upstream project.
