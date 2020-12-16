package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	jwt "github.com/dgrijalva/jwt-go/v4"
	jwk "github.com/lestrrat-go/jwx/jwk"
)

const fileExtension = ".pem"

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

func main() {
	if len(os.Args) != 2 {
		log.Fatal("you should provide a path to directory where to lookup PEM files, e.g. './'")
	}
	dir := os.Args[1]

	filePaths, err := lookupPemFiles(dir)
	if err != nil {
		log.Fatal(err)
	}

	jwkPrivSet := map[string][]jwkPrivAndPubKeyPair{"keys": []jwkPrivAndPubKeyPair{}}
	jwkPubSet := map[string][]jwkPubKey{"keys": []jwkPubKey{}}
	for _, f := range filePaths {
		privKey, err := parseRSAPrivateKeyFromPEM(f)
		if err != nil {
			log.Fatal(err)
		}
		pubKey, err := jwk.PublicKeyOf(privKey)
		if err != nil {
			log.Fatal(err)
		}

		privJwk, err := jwk.New(privKey)
		if err != nil {
			log.Fatal(err)
		}
		// generates Kid using Key.Thumbprint method with crypto.SHA256
		jwk.AssignKeyID(privJwk) //nolint:errcheck

		jwkPub := jwkPubKey{
			Kty: "RSA",
			Alg: "RS256",
			Use: "sig",
			Kid: privJwk.KeyID(),
			N:   safeEncode(pubKey.(*rsa.PublicKey).N.Bytes()),
			E:   safeEncode(big.NewInt(int64(pubKey.(*rsa.PublicKey).E)).Bytes()),
		}
		jwkPriv := jwkPrivAndPubKeyPair{
			jwkPubKey: jwkPub,
			P:         safeEncode(privKey.Primes[0].Bytes()),
			Q:         safeEncode(privKey.Primes[1].Bytes()),
			D:         safeEncode(privKey.D.Bytes()),
			Qi:        safeEncode(privKey.Precomputed.Qinv.Bytes()),
			Dp:        safeEncode(privKey.Precomputed.Dp.Bytes()),
			Dq:        safeEncode(privKey.Precomputed.Dq.Bytes()),
		}
		jwkPrivSet["keys"] = append(jwkPrivSet["keys"], jwkPriv)
		jwkPubSet["keys"] = append(jwkPubSet["keys"], jwkPub)
		fmt.Printf("Kid '%s' - file '%s'\n", jwkPub.Kid, f)
	}
	if err := marshalAndSave(jwkPrivSet, filepath.Join(dir, "jwkPrivate.json")); err != nil {
		log.Fatal(err)
	}
	if err := marshalAndSave(jwkPubSet, filepath.Join(dir, "jwkPublic.json")); err != nil {
		log.Fatal(err)
	}
}

func marshalAndSave(v interface{}, path string) error {
	bytes, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, bytes, 0644)
}

// parsing a PEM encoded PKCS1 or PKCS8 private key
func parseRSAPrivateKeyFromPEM(path string) (*rsa.PrivateKey, error) {
	key, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPrivateKeyFromPEM(key)
}

func lookupPemFiles(dirName string) ([]string, error) {
	fileInfos, err := ioutil.ReadDir(dirName)
	if err != nil {
		return nil, err
	}

	filenames := make([]string, 0)
	for _, f := range fileInfos {
		if f.IsDir() {
			continue
		}

		filename := f.Name()
		if strings.HasSuffix(filename, fileExtension) {
			filenames = append(filenames, filepath.Join(dirName, filename))
		}
	}
	return filenames, nil
}

func safeEncode(p []byte) string {
	data := base64.URLEncoding.EncodeToString(p)
	return strings.TrimRight(data, "=")
}
