package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
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
	jwkPriv, err := RsaPemToJwk(privKeyFile.Name(), jwkAlgRs256)
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
	if jwkPriv[0].N != SafeEncode(pubKey.(*rsa.PublicKey).N.Bytes()) {
		t.Errorf("unexpected JWK public key N: got %s, want %s", jwkPriv[0].N, SafeEncode(pubKey.(*rsa.PublicKey).N.Bytes()))
	}
	if jwkPriv[0].E != SafeEncode(big.NewInt(int64(pubKey.(*rsa.PublicKey).E)).Bytes()) {
		t.Errorf("unexpected JWK public key E: got %s, want %s", jwkPriv[0].E, SafeEncode(big.NewInt(int64(pubKey.(*rsa.PublicKey).E)).Bytes()))
	}
}

func TestRsaPemToJwk_InvalidPemFile(t *testing.T) {
	// Write invalid PEM content to file
	invalidPemFile, err := os.CreateTemp("", "invalid-pem-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(invalidPemFile.Name())
	if _, err := invalidPemFile.Write([]byte("invalid PEM content")); err != nil {
		t.Fatal(err)
	}
	if err := invalidPemFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Ensure that an error is returned when given an invalid PEM file
	if _, err := RsaPemToJwk(invalidPemFile.Name(), jwkAlgRs256); err == nil {
		t.Error("expected error when given invalid PEM file, got nil")
	}
}

func TestRsaPemToJwk_MultipleKeysInPemFile(t *testing.T) {
	// Create two RSA key pairs
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey1 := privKey1.Public()
	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey2 := privKey2.Public()

	// Convert private keys to PEM format
	privKey1Pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey1),
		},
	)
	privKey2Pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey2),
		},
	)

	// Write private keys PEM to file
	keysFile, err := os.CreateTemp("", "rsa-priv-keys-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(keysFile.Name())
	if _, err := keysFile.Write(privKey1Pem); err != nil {
		t.Fatal(err)
	}
	if _, err := keysFile.Write(privKey2Pem); err != nil {
		t.Fatal(err)
	}
	if err := keysFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Convert private keys PEM file to JWK
	jwkPriv, err := RsaPemToJwk(keysFile.Name(), jwkAlgRs256)
	if err != nil {
		t.Fatal(err)
	}

	// Check that JWK private keys contain expected values
	if jwkPriv[0].N != SafeEncode(pubKey1.(*rsa.PublicKey).N.Bytes()) {
		t.Errorf("unexpected JWK public key N: got %s, want %s", jwkPriv[0].N, SafeEncode(pubKey1.(*rsa.PublicKey).N.Bytes()))
	}
	if jwkPriv[0].E != SafeEncode(big.NewInt(int64(pubKey1.(*rsa.PublicKey).E)).Bytes()) {
		t.Errorf("unexpected JWK public key E: got %s, want %s", jwkPriv[0].E, SafeEncode(big.NewInt(int64(pubKey1.(*rsa.PublicKey).E)).Bytes()))
	}
	if jwkPriv[1].N != SafeEncode(pubKey2.(*rsa.PublicKey).N.Bytes()) {
		t.Errorf("unexpected JWK public key N: got %s, want %s", jwkPriv[1].N, SafeEncode(pubKey2.(*rsa.PublicKey).N.Bytes()))
	}
	if jwkPriv[1].E != SafeEncode(big.NewInt(int64(pubKey2.(*rsa.PublicKey).E)).Bytes()) {
		t.Errorf("unexpected JWK public key E: got %s, want %s", jwkPriv[1].E, SafeEncode(big.NewInt(int64(pubKey2.(*rsa.PublicKey).E)).Bytes()))
	}
}

func TestRsaPemToJwk_NonExistentPemFile(t *testing.T) {
	// Ensure that an error is returned when given a non-existent PEM file
	if _, err := RsaPemToJwk("non-existent-file.pem", jwkAlgRs256); err == nil {
		t.Error("expected error when given non-existent PEM file, got nil")
	}
}

func TestRsaPemToJwk_NonPemFile(t *testing.T) {
	// Write non-PEM data to a temporary file
	nonPemFile, err := os.CreateTemp("", "non-pem-file-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(nonPemFile.Name())
	if _, err := nonPemFile.Write([]byte("this is not a PEM file")); err != nil {
		t.Fatal(err)
	}
	if err := nonPemFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Ensure that an error is returned when given a non-PEM file
	if _, err := RsaPemToJwk(nonPemFile.Name(), jwkAlgRs256); err == nil {
		t.Error("expected error when given non-PEM file, got nil")
	}
}
func TestRsaPemToJwk_MultipleKeysPemFile(t *testing.T) {
	// Create RSA key pair 1
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey1 := privKey1.Public()

	// Convert private key 1 to PEM format
	privKey1Pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey1),
		},
	)

	// Create RSA key pair 2
	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey2 := privKey2.Public()

	// Convert private key 2 to PEM format
	privKey2Pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey2),
		},
	)

	// Write both private keys to a PEM file
	privKeysPemFile, err := os.CreateTemp("", "rsa-priv-keys-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(privKeysPemFile.Name())
	if _, err := privKeysPemFile.Write(privKey1Pem); err != nil {
		t.Fatal(err)
	}
	if _, err := privKeysPemFile.Write(privKey2Pem); err != nil {
		t.Fatal(err)
	}
	if err := privKeysPemFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Convert private keys PEM file to JWK
	jwkPriv, err := RsaPemToJwk(privKeysPemFile.Name(), jwkAlgRs256)
	if err != nil {
		t.Fatal(err)
	}

	// Check that JWK private keys contain expected values
	if len(jwkPriv) != 2 {
		t.Errorf("unexpected number of JWK private keys: got %d, want 2", len(jwkPriv))
	}
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
	if jwkPriv[0].N != SafeEncode(pubKey1.(*rsa.PublicKey).N.Bytes()) {
		t.Errorf("unexpected JWK public key N: got %s, want %s", jwkPriv[0].N, SafeEncode(pubKey1.(*rsa.PublicKey).N.Bytes()))
	}
	if jwkPriv[0].E != SafeEncode(big.NewInt(int64(pubKey1.(*rsa.PublicKey).E)).Bytes()) {
		t.Errorf("unexpected JWK public key E: got %s, want %s", jwkPriv[0].E, SafeEncode(big.NewInt(int64(pubKey1.(*rsa.PublicKey).E)).Bytes()))
	}
	if jwkPriv[1].Kty != jwkKtyRsa {
		t.Errorf("unexpected JWK public key use: got %s, want %s", jwkPriv[1].Use, jwkUseSig)
	}
	if jwkPriv[1].Alg != jwkAlgRs256 {
		t.Errorf("unexpected JWK public key algorithm: got %s, want %s", jwkPriv[1].Alg, jwkAlgRs256)
	}
	if jwkPriv[1].N != SafeEncode(pubKey2.(*rsa.PublicKey).N.Bytes()) {
		t.Errorf("unexpected JWK public key N: got %s, want %s", jwkPriv[1].N, SafeEncode(pubKey2.(*rsa.PublicKey).N.Bytes()))
	}
	if jwkPriv[1].E != SafeEncode(big.NewInt(int64(pubKey2.(*rsa.PublicKey).E)).Bytes()) {
		t.Errorf("unexpected JWK public key E: got %s, want %s", jwkPriv[1].E, SafeEncode(big.NewInt(int64(pubKey2.(*rsa.PublicKey).E)).Bytes()))
	}
}

func TestRsaPemToJwk_NonExistentFile(t *testing.T) {
	if _, err := RsaPemToJwk("non-existent-file.pem", jwkAlgRs256); err == nil {
		t.Error("expected error when given non-existent file, got nil")
	}
}

func TestMarshalAndSave(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp(os.TempDir(), "test-marshal-and-save-*.dir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Prepare data to be marshaled and saved
	data := map[string]string{"key": "value"}

	// Marshal and save data to a file in the temporary directory
	filePath := filepath.Join(tempDir, "test-file.json")
	if err := MarshalAndSave(data, filePath); err != nil {
		t.Fatal(err)
	}

	// Read saved data from file
	savedData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal saved data
	var unmarshaledData map[string]string
	if err := json.Unmarshal(savedData, &unmarshaledData); err != nil {
		t.Fatal(err)
	}

	// Check that unmarshaled data is equal to the original data
	if !reflect.DeepEqual(unmarshaledData, data) {
		t.Errorf("unexpected unmarshaled data: got %v, want %v", unmarshaledData, data)
	}
}

func TestLookupPemFiles(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp(os.TempDir(), "test-lookup-pem-files-*.dir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create PEM files in the temporary directory
	for i := 0; i < 3; i++ {
		filePath := filepath.Join(tempDir, fmt.Sprintf("file-%d.pem", i))
		if err := os.WriteFile(filePath, []byte("test data"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Create non-PEM file in the temporary directory
	if err := os.WriteFile(filepath.Join(tempDir, "file.txt"), []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Look up PEM files in the temporary directory
	filePaths, err := LookupPemFiles(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the returned file paths are correct
	expectedFilePaths := []string{
		filepath.Join(tempDir, "file-0.pem"),
		filepath.Join(tempDir, "file-1.pem"),
		filepath.Join(tempDir, "file-2.pem"),
	}
	if !reflect.DeepEqual(filePaths, expectedFilePaths) {
		t.Errorf("unexpected file paths: got %v, want %v", filePaths, expectedFilePaths)
	}
}

func TestSafeEncode(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		output string
	}{
		{
			name:   "empty input",
			input:  []byte{},
			output: "",
		},
		{
			name:   "non-empty input",
			input:  []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
			output: "ASNFZ4mrze8",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := SafeEncode(test.input)
			if result != test.output {
				t.Errorf("unexpected result: got %s, want %s", result, test.output)
			}
		})
	}
}

func TestRsaPemToJwk_NilFilename(t *testing.T) {
	_, err := RsaPemToJwk("", jwkAlgRs256)
	if err == nil {
		t.Error("expected error when given empty filename, got nil")
	}
}

func TestRsaPemToJwk_UnreadableFile(t *testing.T) {
	// Create an unreadable file
	file, err := os.CreateTemp("", "unreadable-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file.Name(), 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	_, err = RsaPemToJwk(file.Name(), jwkAlgRs256)
	if err == nil {
		t.Error("expected error when given unreadable file, got nil")
	}
}

func TestRsaPemToJwk_NotFoundFile(t *testing.T) {
	_, err := RsaPemToJwk("non-existent-file.pem", jwkAlgRs256)
	if err == nil {
		t.Error("expected error when given non-existent file, got nil")
	}
}

func TestRsaPemToJwk_InvalidPrivateKey(t *testing.T) {
	// Create an invalid PEM file (missing BEGIN/END RSA PRIVATE KEY headers)
	file, err := os.CreateTemp("", "invalid-private-key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	if _, err := file.Write([]byte("invalid private key")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = RsaPemToJwk(file.Name(), jwkAlgRs256)
	if err == nil {
		t.Error("expected error when given invalid private key PEM file, got nil")
	}
}

func TestCheckPrivKeyRequirements(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Error generating private key: %v", err)
	}

	err = checkPrivKeyRequirements(privKey, jwkAlgRs256)
	if err == nil {
		t.Errorf("Expected error for key size too small")
	}

	privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error generating private key: %v", err)
	}

	err = checkPrivKeyRequirements(privKey, jwkAlgRs256)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	err = checkPrivKeyRequirements(privKey, "invalid")
	if err == nil {
		t.Errorf("Expected error for invalid algorithm")
	}

	err = checkPrivKeyRequirements(privKey, jwkAlgRs384)
	if err == nil {
		t.Errorf("Expected error for key size too small")
	}

	err = checkPrivKeyRequirements(privKey, jwkAlgRs512)
	if err == nil {
		t.Errorf("Expected error for key size too small")
	}
}

func TestConvert(t *testing.T) {
	// create a temporary directory to hold PEM files
	tempDir, err := os.MkdirTemp("", "pem-to-jwk-*")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// create some PEM files with different sizes
	keySizes := []int{256, 384, 512}
	for i, size := range keySizes {
		filename := fmt.Sprintf("key%d.pem", i)
		fullPath := filepath.Join(tempDir, filename)
		if err = createPemFile(fullPath, size); err != nil {
			t.Fatalf("Failed to create PEM file: %v", err)
		}
	}

	// call the Convert function with the temporary directory and RS256 algorithm
	err = Convert(tempDir, jwkAlgRs256)
	if err != nil {
		t.Fatalf("Convert failed: %v", err)
	}
}

func createPemFile(filename string, keySize int) error {
	// generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize*8)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// encode private key to PEM format
	pemKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	pemData := pem.EncodeToMemory(pemKey)

	// write to file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if _, err := io.WriteString(file, string(pemData)); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}
