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

	cli "github.com/jawher/mow.cli"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

const fileExtension = ".pem"
const jsonJwkPrivFilename = "rsa2jwk_jwkPrivate.json"
const jsonJwkPubFilename = "rsa2jwk_jwkPublic.json"

const jwkKtyRsa = "RSA"
const jwkAlgRs256 = "RS256"
const jwkAlgRs384 = "RS384"
const jwkAlgRs512 = "RS512"
const jwkUseSig = "sig"

const keySizeErr = "key size %d is too small for algorithm %s, it should be equal or greater than %d"

type jwkPrivAndPubKeyPair struct {
	jwkPubKey
	P  string `json:"p"`
	Q  string `json:"q"`
	D  string `json:"d"`
	Qi string `json:"qi"`
	Dp string `json:"dp"`
	Dq string `json:"dq"`
}

// JwkPrivAndPubKeyPairs returns JWT public and private pairs as a slice
type JwkPrivAndPubKeyPairs []jwkPrivAndPubKeyPair

type jwkPubKey struct {
	Kty string `json:"kty"`
	E   string `json:"e"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
}

// RsaPemToJwk converts a PEM file containing an RSA key pair to a JWK private and public key pair.
func RsaPemToJwk(path, alg string) (JwkPrivAndPubKeyPairs, error) {
	jwkPrivSet := JwkPrivAndPubKeyPairs{}

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
		if err = checkPrivKeyRequirements(privKey, alg); err != nil {
			return nil, err
		}

		pubKey := privKey.Public()

		privJwk, err := jwk.FromRaw(privKey)
		if err != nil {
			return nil, err
		}
		// generates Kid using Key.Thumbprint method with crypto.SHA256
		jwk.AssignKeyID(privJwk) // nolint:errcheck

		jwkPub := jwkPubKey{ // nolint:forcetypeassert
			Kty: jwkKtyRsa,
			Alg: alg,
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

func checkPrivKeyRequirements(privateKey *rsa.PrivateKey, alg string) error {
	var err error
	keySize := privateKey.Size()
	switch alg {
	case jwkAlgRs256:
		if keySize < 256 {
			err = fmt.Errorf(keySizeErr, keySize, alg, 256)
		}
	case jwkAlgRs384:
		if keySize < 384 {
			err = fmt.Errorf(keySizeErr, keySize, alg, 384)
		}
	case jwkAlgRs512:
		if keySize < 512 {
			err = fmt.Errorf(keySizeErr, keySize, alg, 512)
		}
	default:
		err = fmt.Errorf("algorithm %s is not supported", alg)
	}

	return err
}

// MarshalAndSave marshals the given data to JSON and saves it to the specified file.
func MarshalAndSave(data interface{}, path string) error {
	jsonData, err := json.MarshalIndent(data, "", " ")
	if err != nil {
		return err
	}
	file, err := os.Create(path) // nolint: gosec
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
	app := cli.App("rsa2jwk", "Converts Single or Multiple RSA pem to JWK Private and Public sets (json files)")
	app.Spec = "[-a] DIR"

	var (
		dir = app.StringArg("DIR", ".", "Directory where to lookup PEM files")
		alg = app.StringOpt("a alg", "RS256", "Algorithm to use for the JWK keys")
	)

	// Specify the action to execute when the app is invoked correctly
	app.Action = func() {
		if err := Convert(*dir, *alg); err != nil {
			log.Fatal(err)
		}
	}

	// Invoke the app passing in os.Args
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

// Convert converts PEM files to JWK private and public key pairs
func Convert(dir, alg string) error {
	// verify alg is a valid algorithm, one of RS256, RS384, RS512
	switch alg {
	case jwkAlgRs256, jwkAlgRs384, jwkAlgRs512:
	default:
		log.Fatalf("invalid algorithm, must be one of %s, %s, %s", jwkAlgRs256, jwkAlgRs384, jwkAlgRs512)
	}

	filePaths, err := LookupPemFiles(dir)
	if err != nil {
		return err
	}

	jwkPrivSet := map[string][]jwkPrivAndPubKeyPair{"keys": {}}
	jwkPubSet := map[string][]jwkPubKey{"keys": {}}
	fmt.Printf("%43s\t%s\n", "Kid", "Filename")
	for _, f := range filePaths {
		jwkPriv, err := RsaPemToJwk(f, alg)
		if err != nil {
			return err
		}
		for _, jwkPrivAndPub := range jwkPriv {
			jwkPrivSet["keys"] = append(jwkPrivSet["keys"], jwkPrivAndPub)
			jwkPubSet["keys"] = append(jwkPubSet["keys"], jwkPrivAndPub.jwkPubKey)
			fmt.Printf("%s\t%s\n", jwkPrivAndPub.jwkPubKey.Kid, f)
		}
	}
	if err := MarshalAndSave(jwkPrivSet, filepath.Join(dir, jsonJwkPrivFilename)); err != nil {
		return err
	}

	return MarshalAndSave(jwkPubSet, filepath.Join(dir, jsonJwkPubFilename))
}
