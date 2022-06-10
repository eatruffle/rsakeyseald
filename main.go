package main

import "fmt"

func main() {

	prvKey, pubKeyStr := InitCryptoMaterialForHSM("secret","password")

	fmt.Println(prvKey)
	fmt.Println(pubKeyStr)

}
