# rsa2jwk

Converts Single or Multiple RSA pem (PKCS1/PKCS8 serializaed as "AQAB") to JWK Private and Public sets (json files).

RSA private key could be generated using openssl like `openssl genrsa -out private-key.pem 2048`

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
# Kid '5lUPIy6kHHaYBpTQscwg15UCR39O1zyWJG6neFG2bTk' - file 'tmp/test.pem'
```

```sh
cat tmp/jwkPublic.json | jq
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
