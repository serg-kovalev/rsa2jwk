package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const fileExtension = ".pem"
const jsonJwkPrivFilename = "rsa2jwk_jwkPrivate.json"
const jsonJwkPubFilename = "rsa2jwk_jwkPublic.json"

const jwkKtyRsa = "RSA"
const jwkAlgRs256 = "RS256"
const jwkUseSig = "sig"

type jwkPrivAndPubKeyPair struct {
	jwkPubKey
	P  string `json:"p"`
	Q  string `json:"q"`
	D  string `json:"d"`
	Qi string `json:"qi"`
	Dp string `json:"dp"`
	Dq string `json:"dq"`
}

type jwkPubKey struct {
	Kty string `json:"kty"`
	E   string `json:"e"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
}

// RsaPemToJwk converts a PEM file containing an RSA key pair to a JWK private and public key pair.
func RsaPemToJwk(path string) ([]jwkPrivAndPubKeyPair, error) {
	jwkPrivSet := []jwkPrivAndPubKeyPair{}

	jwkSet, err := jwk.ReadFile(path, jwk.WithPEM(true))
	if err != nil {
		return nil, err
	}
	for i := 0; i < jwkSet.Len(); i++ {
		var rawKey interface{}
		jwkKey, _ := jwkSet.Key(i)
		err = jwkKey.Raw(&rawKey)
		if err != nil {
			return nil, err
		}
		privKey, ok := rawKey.(*rsa.PrivateKey)
		if !ok {
			return nil, err
		}
		pubKey := privKey.Public()

		privJwk, err := jwk.FromRaw(privKey)
		if err != nil {
			return nil, err
		}
		// generates Kid using Key.Thumbprint method with crypto.SHA256
		jwk.AssignKeyID(privJwk) //nolint:errcheck

		jwkPub := jwkPubKey{
			Kty: jwkKtyRsa,
			Alg: jwkAlgRs256,
			Use: jwkUseSig,
			Kid: privJwk.KeyID(),
			N:   SafeEncode(pubKey.(*rsa.PublicKey).N.Bytes()),
			E:   SafeEncode(big.NewInt(int64(pubKey.(*rsa.PublicKey).E)).Bytes()),
		}
		jwkPriv := jwkPrivAndPubKeyPair{
			jwkPubKey: jwkPub,
			P:         SafeEncode(privKey.Primes[0].Bytes()),
			Q:         SafeEncode(privKey.Primes[1].Bytes()),
			D:         SafeEncode(privKey.D.Bytes()),
			Qi:        SafeEncode(privKey.Precomputed.Qinv.Bytes()),
			Dp:        SafeEncode(privKey.Precomputed.Dp.Bytes()),
			Dq:        SafeEncode(privKey.Precomputed.Dq.Bytes()),
		}
		jwkPrivSet = append(jwkPrivSet, jwkPriv)
	}

	return jwkPrivSet, nil
}

// MarshalAndSave marshals the given data to JSON and saves it to the specified file.
func MarshalAndSave(data interface{}, path string) error {
	jsonData, err := json.MarshalIndent(data, "", " ")
	if err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(jsonData)
	return err
}

// SafeEncode encodes the given data to a base64 string, with padding stripped.
func SafeEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// LookupPemFiles looks up PEM files in the given directory and returns their paths.
func LookupPemFiles(dir string) ([]string, error) {
	filePaths := []string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == fileExtension {
			filePaths = append(filePaths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return filePaths, nil
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("you should provide a path to a directory where to lookup PEM files, e.g. './'")
	}
	dir := os.Args[1]
	filePaths, err := LookupPemFiles(dir)
	if err != nil {
		log.Fatal(err)
	}

	jwkPrivSet := map[string][]jwkPrivAndPubKeyPair{"keys": {}}
	jwkPubSet := map[string][]jwkPubKey{"keys": {}}
	fmt.Printf("%43s\t%s\n", "Kid", "Filename")
	for _, f := range filePaths {
		jwkPriv, err := RsaPemToJwk(f)
		if err != nil {
			log.Fatal(err)
		}
		for _, jwkPrivAndPub := range jwkPriv {
			jwkPrivSet["keys"] = append(jwkPrivSet["keys"], jwkPrivAndPub)
			jwkPubSet["keys"] = append(jwkPubSet["keys"], jwkPrivAndPub.jwkPubKey)
			fmt.Printf("%s\t%s\n", jwkPrivAndPub.jwkPubKey.Kid, f)
		}
	}
	if err := MarshalAndSave(jwkPrivSet, filepath.Join(dir, jsonJwkPrivFilename)); err != nil {
		log.Fatal(err)
	}
	if err := MarshalAndSave(jwkPubSet, filepath.Join(dir, jsonJwkPubFilename)); err != nil {
		log.Fatal(err)
	}
}
