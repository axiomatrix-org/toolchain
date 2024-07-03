package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

var keypair map[string]string = nil

// 產生KeyPair
func GenRSAKeyPair(bits int) (privateKey, publicKey string, err error) {
	if keypair != nil {
		return
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}
	pkcs1PrivateKey := x509.MarshalPKCS1PrivateKey(key)

	p := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs1PrivateKey,
	}

	privKeyPEM := pem.EncodeToMemory(p)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}

	p = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	pubKeyPEM := pem.EncodeToMemory(p)

	privateKey = string(privKeyPEM)
	publicKey = string(pubKeyPEM)

	keypair = map[string]string{
		"private": privateKey,
		"public":  publicKey,
	}
	return
}

// 加密
func RsaEncryptBase64(originalData, publicKey string) (string, error) {
	block, _ := pem.Decode([]byte(publicKey))
	pubKey, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
	if parseErr != nil {
		return "", errors.New("Fail to parse public key")
	}
	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey.(*rsa.PublicKey), []byte(originalData))
	return base64.StdEncoding.EncodeToString(encryptedData), err
}

// 解密
func RsaDecryptBase64(encryptedData, privateKey string) (string, error) {
	encryptedDecodeBytes, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode([]byte(privateKey))
	priKey, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
	if parseErr != nil {
		return "", errors.New("Fail to parse private key")
	}

	originalData, encryptErr := rsa.DecryptPKCS1v15(rand.Reader, priKey, encryptedDecodeBytes)
	return string(originalData), encryptErr
}
