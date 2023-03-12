# rsa2jwk

[![GitHub version](https://badge.fury.io/gh/serg-kovalev%2Frsa2jwk.svg)](https://badge.fury.io/gh/serg-kovalev%2Frsa2jwk)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/serg-kovalev/rsa2jwk/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/serg-kovalev/rsa2jwk)](https://goreportcard.com/report/github.com/serg-kovalev/rsa2jwk)
[![CI](https://github.com/serg-kovalev/rsa2jwk/actions/workflows/ci.yml/badge.svg?query=branch%3Amain+event%3Apush)](https://github.com/serg-kovalev/rsa2jwk/actions/workflows/ci.yml?query=branch%3Amain+event%3Apush)
[![CodeQL](https://github.com/serg-kovalev/rsa2jwk/actions/workflows/codeql-analysis.yml/badge.svg?query=branch%3Amain+event%3Apush)](https://github.com/serg-kovalev/rsa2jwk/actions/workflows/codeql-analysis.yml?query=branch%3Amain+event%3Apush)
[![Maintainability](https://api.codeclimate.com/v1/badges/c5a82c115d4415d97ef1/maintainability)](https://codeclimate.com/github/serg-kovalev/rsa2jwk/maintainability)

# Overview

Converts Single or Multiple RSA pem (PKCS1/PKCS8 serialized as "AQAB") to JWK Private and Public sets (json files).

RSA private key could be generated using openssl like `openssl genrsa -out private-key.pem 2048`

# Download the latest release

Please find the latest release [here](https://github.com/serg-kovalev/rsa2jwk/releases)

## Build

```sh
go build
```

## CLI Usage

```sh
Usage: rsa2jwk [-a] DIR

Converts Single or Multiple RSA pem to JWK Private and Public sets (json files)

Arguments:
  DIR          Directory where to lookup PEM files (default ".")

Options:
  -a, --alg    Algorithm to use for the JWK keys (default "RS256")
```

It supports the following algorithms:

- RS256
- RS384
- RS512

The tool verifies the private key size according to specification in RFC 7518. Specifically, section 6.3.1 of the RFC defines the required key sizes for each algorithm as follows:

- **RS256**: The key size _MUST be 2048 bits or larger_
- **RS384**: The key size _MUST be 3072 bits or larger_
- **RS512**: The key size _MUST be 4096 bits or larger_

## CLI Usage Example

```sh
rsa2jwk tmp
# Output:
#                                        Kid	Filename
#5lUPIy6kHHaYBpTQscwg15UCR39O1zyWJG6neFG2bTk	tmp/test.pem
```

W/o headers:

```sh
rsa2jwk tmp | tail -n 1
#5lUPIy6kHHaYBpTQscwg15UCR39O1zyWJG6neFG2bTk	tmp/test.pem
```

In the specified folder you will find two newly generated files:

- `rsa2jwk_jwkPrivate.json`
- `rsa2jwk_jwkPublic.json`

```sh
cat tmp/rsa2jwk_jwkPublic.json | jq
```

Output:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "5lUPIy6kHHaYBpTQscwg15UCR39O1zyWJG6neFG2bTk",
      "alg": "RS256",
      "n": "16ClrRqxEX_73X0VTzOmoGpuOnNqHb425CyyAaoAWcoqMR1sFNOnrPeEzhRbJfDJ5SIQLCUzLIwxsWtiDxZnHS7D9BahtXCBwfokXkAZFDcyJPxEluV1I5VHyl-3uDuoLll2EkBd3v5AfXjwdPDmvVr9ugV52u5VSGr-j630dtzpc47QB9EgGN_RlQGGPQusJ3uEFy0k3ivDgsFbmZCUdfZFNfm30NjxIwBIzeTdWKdsSrwok7rla1TuveuaUjt-HBjImHHH47ocJq78OlAdJh5Mh2BRBHRwWvIJIChQ-MK-jJoef1u0Su15U4CsfWk7Dw7XbBOw9jdyOjuNNO50Dw"
    }
  ]
}
```

## Package

To use this program as a package, you can simply import it into another Go file and call the functions in the same way they are called in the main function. For example:

```go
import "github.com/serg-kovalev/rsa2jwk"

// ...

filePaths, err := rsa2jwk.LookupPemFiles(dir)
if err != nil {
	log.Fatal(err)
}

jwkPriv, err := rsa2jwk.RsaPemToJwk(filePaths[0], "RS256")
if err != nil {
	log.Fatal(err)
}

err = rsa2jwk.MarshalAndSave(jwkPriv, "jwk.json")
if err != nil {
	log.Fatal(err)
}
```

## Contributing

[Contributing](./CONTRIBUTING.md)

## Code of Conduct

[Code of Conduct](./CODE_OF_CONDUCT.md)
