# pqcvet

A `go vet`-style static analyzer that flags **quantum-vulnerable cryptography**
in Go source. Built on `golang.org/x/tools/go/analysis`, so it composes with
`go vet`, `golangci-lint`, and any CI pipeline that already runs them.

## Install

Requires Go 1.25 or later (`x/tools` v0.46.0 floor; `crypto/mlkem`
detection works on the same toolchain).

The module path `pqcvet` is a local placeholder; `go install` will not
resolve until the module is republished under a distribution path
(e.g. `github.com/<you>/pqcvet`). For now, clone and build from source:

```sh
git clone <repo> && cd pqcvet
go build ./cmd/pqcvet
```

## Use

```sh
pqcvet ./...           # vet-style diagnostics
pqcvet -format json ./...   # aggregated JSON report
```

Composes with golangci-lint via the custom-analyzer extension, or invoke
directly from a CI step. Exit codes follow the `go/analysis`
singlechecker/unitchecker convention: 0 clean, 1 on package load errors,
2 on internal errors (bad flag, encode failure), 3 when findings are
present. Text and JSON modes use the same codes.

## Scope

**v1 emits diagnostics and an aggregated JSON report.** A cryptographic
asset inventory (CBOM — CycloneDX 1.6) is planned and is tracked as a
separate milestone. Today the tool walks every type-resolved selector,
matches the resolved `(import-path, symbol)` pair against a rule table,
and reports flagged uses with `pass.Report`. The same findings are
returned as the analyzer result and surface via the `-format json`
driver for downstream tools.

### Detected algorithms (v1)

Shor-vulnerable asymmetric (flagged):

- `crypto/rsa` — `GenerateKey`, `Sign`/`SignPKCS1v15`/`SignPSS`,
  `Verify{PKCS1v15,PSS}`, `{Encrypt,Decrypt}OAEP`, `{Encrypt,Decrypt}PKCS1v15`,
  `Decrypt` (the `*PrivateKey.Decrypt` method on parsed keys)
- `crypto/ecdsa` — `GenerateKey`, `Sign`, `SignASN1`, `Verify`, `VerifyASN1`
- `crypto/ed25519` — `GenerateKey`, `Sign`, `Verify`, `VerifyWithOptions`,
  `NewKeyFromSeed`
- `crypto/ecdh` — `GenerateKey`, `NewPrivateKey`, `NewPublicKey`, and the
  `*PrivateKey.ECDH` shared-secret method (curve constructors intentionally
  skipped to avoid double-flagging — see Known limitations)
- `crypto/dsa` — entire package (catch-all)

Classically broken (flagged, severity-overridden to MEDIUM):

- `crypto/md5`, `crypto/sha1` — `New`, `Sum`
- `crypto/des` — `NewCipher`, `NewTripleDESCipher`
- `crypto/rc4` — `NewCipher`
- `crypto` — `MD5`, `SHA1`, `MD5SHA1` Hash-registry constants (e.g.
  `crypto.SHA1.New()` used in signing/HMAC configs)

Post-quantum safe (recorded only, no diagnostic):

- `crypto/mlkem` — entire package (catch-all)

`crypto/mldsa` will be added when it lands in the standard library (or
for a third-party implementation in a later milestone).

## Severity model

Every detected algorithm is classified on two axes:

| Exposure × Purpose         | keyex / encryption | signature | symmetric / hash |
|----------------------------|--------------------|-----------|------------------|
| `shor` (asymmetric)        | **HIGH**           | MEDIUM    | n/a              |
| `grover` (symmetric)       | n/a                | n/a       | LOW              |
| `classical` (already broken)| n/a (override)    | n/a (override) | n/a (override) |
| `safe` (PQC / hybrid)      | INFO (recorded)    | INFO      | INFO             |

- **HIGH** for Shor + key-exchange/encryption captures *harvest-now-decrypt-later*
  risk: traffic an adversary records today can be decrypted once a sufficiently
  large quantum computer exists.
- **MEDIUM** for Shor + signature, because captured signatures lose value once
  a quantum computer is available; forgery is the only remaining risk.
- **INFO** for known-safe (PQC) algorithms: recorded for the future CBOM but
  not emitted as diagnostics.

Rule entries may override the matrix per-algorithm. The `classical` exposure
relies entirely on this: MD5/SHA-1/DES/RC4 are broken without quantum help, so
the matrix has no cells for them and rules carry an explicit `Severity` field
(MEDIUM) that drives the diagnostic.

## Known limitations

- **Symmetric key size is statically undecidable.** `aes.NewCipher(key)` takes
  a runtime `[]byte`; the length is almost never a compile-time constant. The
  tool does not attempt AES-128 vs AES-256 detection from key material; doing
  so would produce false positives or false negatives in idiomatic code.
- **Method dispatch through `crypto.Signer`** (or any other interface declared
  in package `crypto`) resolves to package `crypto`, not the concrete algorithm
  package — so the method call cannot be tied back to ECDSA/Ed25519/RSA. The
  surrounding key construction (`ecdsa.GenerateKey`, parsed key, etc.) is
  still flagged. Concrete-typed method calls (`priv.Sign(...)` on
  `*ecdsa.PrivateKey`, `priv.Decrypt(...)` on `*rsa.PrivateKey`,
  `priv.ECDH(peer)` on `*ecdh.PrivateKey`) **are** caught — rule entries list
  the method names so resolution lands on the algorithm package directly.
- **`crypto/x509` and `crypto/tls`** choose algorithms at runtime from
  configuration and certificate contents. Static symbol matching catches very
  little of practical value here; semantic checks for these packages are
  planned but intentionally absent in v1.
- **`crypto/elliptic` curve constructors** are not in the rule table even
  though they're Shor-vulnerable, because they're almost always passed into
  `ecdsa.GenerateKey`, which already fires — adding them would double-report
  the same line.

## Development

```sh
go build ./...
go vet ./...
go test ./... -race
gofmt -l .   # must be empty
```

## License

MIT. See [LICENSE](LICENSE).
