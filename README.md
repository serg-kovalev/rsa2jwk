# rsa2jwk

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/serg-kovalev/rsa2jwk/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/serg-kovalev/rsa2jwk)](https://goreportcard.com/report/github.com/serg-kovalev/rsa2jwk)

# Overview

Converts Single or Multiple RSA pem (PKCS1/PKCS8 serialized as "AQAB") to JWK Private and Public sets (json files).

RSA private key could be generated using openssl like `openssl genrsa -out private-key.pem 2048`

# Download the latest release

Please find the latest release [here](https://github.com/serg-kovalev/rsa2jwk/releases)

## Build

```sh
go build
```

## Usage

```sh
rsa2jwk path/to/folder_with_pem
```

## Example

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
