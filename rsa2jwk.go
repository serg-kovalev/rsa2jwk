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

	jwk "github.com/lestrrat-go/jwx/v2/jwk"
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

func main() {
	if len(os.Args) != 2 {
		log.Fatal("you should provide a path to a directory where to lookup PEM files, e.g. './'")
	}
	dir := os.Args[1]

	filePaths, err := lookupPemFiles(dir)
	if err != nil {
		log.Fatal(err)
	}

	jwkPrivSet := map[string][]jwkPrivAndPubKeyPair{"keys": {}}
	jwkPubSet := map[string][]jwkPubKey{"keys": {}}
	fmt.Printf("%43s\t%s\n", "Kid", "Filename")
	for _, f := range filePaths {
		jwkSet, err := jwk.ReadFile(f, jwk.WithPEM(true))
		if err != nil {
			log.Fatal(err)
		}
		for i := 0; i < jwkSet.Len(); i++ {
			var rawKey interface{}
			jwkKey, _ := jwkSet.Key(i)
			err = jwkKey.Raw(&rawKey)
			if err != nil {
				log.Fatal(err)
			}
			privKey, ok := rawKey.(*rsa.PrivateKey)
			if !ok {
				log.Fatal("provided key is not private one")
			}
			pubKey := privKey.Public()

			privJwk, err := jwk.FromRaw(privKey)
			if err != nil {
				log.Fatal(err)
			}
			// generates Kid using Key.Thumbprint method with crypto.SHA256
			jwk.AssignKeyID(privJwk) //nolint:errcheck

			jwkPub := jwkPubKey{
				Kty: jwkKtyRsa,
				Alg: jwkAlgRs256,
				Use: jwkUseSig,
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
			fmt.Printf("%s\t%s\n", jwkPub.Kid, f)
		}
	}

	if err := marshalAndSave(jwkPrivSet, filepath.Join(dir, jsonJwkPrivFilename)); err != nil {
		log.Fatal(err)
	}
	if err := marshalAndSave(jwkPubSet, filepath.Join(dir, jsonJwkPubFilename)); err != nil {
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
