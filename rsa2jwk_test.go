package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
)

func TestRsaPemToJwk(t *testing.T) {
	// Create RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := privKey.Public()

	// Convert private key to PEM format
	privKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)

	// Write private key PEM to file
	privKeyFile, err := os.CreateTemp("", "rsa-priv-key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(privKeyFile.Name())
	if _, err := privKeyFile.Write(privKeyPem); err != nil {
		t.Fatal(err)
	}
	if err := privKeyFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Convert private key PEM file to JWK
	jwkPriv, err := rsaPemToJwk(privKeyFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Check that JWK private key contains expected values
	if jwkPriv[0].Kty != jwkKtyRsa {
		t.Errorf("unexpected JWK private key type: got %s, want %s", jwkPriv[0].Kty, jwkKtyRsa)
	}
	if jwkPriv[0].Use != jwkUseSig {
		t.Errorf("unexpected JWK public key type: got %s, want %s", jwkPriv[0].Kty, jwkKtyRsa)
	}
	if jwkPriv[0].Use != jwkUseSig {
		t.Errorf("unexpected JWK public key use: got %s, want %s", jwkPriv[0].Use, jwkUseSig)
	}
	if jwkPriv[0].Alg != jwkAlgRs256 {
		t.Errorf("unexpected JWK public key algorithm: got %s, want %s", jwkPriv[0].Alg, jwkAlgRs256)
	}
	if jwkPriv[0].N != safeEncode(pubKey.(*rsa.PublicKey).N.Bytes()) {
		t.Errorf("unexpected JWK public key N: got %s, want %s", jwkPriv[0].N, safeEncode(pubKey.(*rsa.PublicKey).N.Bytes()))
	}
	if jwkPriv[0].E != safeEncode(big.NewInt(int64(pubKey.(*rsa.PublicKey).E)).Bytes()) {
		t.Errorf("unexpected JWK public key E: got %s, want %s", jwkPriv[0].E, safeEncode(big.NewInt(int64(pubKey.(*rsa.PublicKey).E)).Bytes()))
	}
}
