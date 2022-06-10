package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/edgelesssys/ego/ecrypto"
	"io/ioutil"
	"os"
)

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func ConvertPubKeyToString(pubKey *rsa.PublicKey) string {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		fmt.Printf("error when dumping publickey: %s \n", err)
		os.Exit(1)
	}

	b64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	fmt.Println(b64)

	return b64
}

func UnsealPrvKey(filePath, passwordPhrase string) *rsa.PrivateKey {

	passwordPhraseByte := []byte(passwordPhrase)

	sealdKeyByte, err := ioutil.ReadFile(filePath)

	if err != nil {
		fmt.Println("Problem with read seald key file")
	}

	unSealdKeyBytes, err := ecrypto.Unseal(sealdKeyByte, passwordPhraseByte)

	if err != nil {
		fmt.Println("Error during unseal process")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(unSealdKeyBytes)

	return privateKey
}

func SealPrvKey(key *rsa.PrivateKey, passwordPhrase, filePath string) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	passwordPhraseByte := []byte(passwordPhrase)
	enc, err := ecrypto.SealWithUniqueKey(privateKeyBytes, passwordPhraseByte)

	if err != nil {
		fmt.Println("Out")
	}

	err = ioutil.WriteFile(filePath, enc, 0600)

	if err != nil {
		fmt.Println("Out")
	}
}

func InitCryptoMaterialForHSM(filePath, passwordPhrase string) (*rsa.PrivateKey, string) {

	if FileExists(filePath) {

		fmt.Println("file exist")

		privateKey := UnsealPrvKey(filePath, passwordPhrase)

		publicKey := &privateKey.PublicKey

		pubKeyStr := ConvertPubKeyToString(publicKey)

		return privateKey, pubKeyStr

	} else {

		fmt.Println("file not exists")

		privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("Cannot generate RSA key\n")
			os.Exit(1)
		}

		SealPrvKey(privatekey, passwordPhrase, filePath)

		publickey := &privatekey.PublicKey

		pubKeyStr := ConvertPubKeyToString(publickey)
		return privatekey, pubKeyStr
	}
}