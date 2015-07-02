package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func main() {
	c := elliptic.P256()
	priv, x, y, err := elliptic.GenerateKey(c, rand.Reader)
	if err != nil {
		fmt.Printf("Error!\n")
	} else {
		fmt.Printf("Public Key is %s\n Private key is %s\n",
			base64.StdEncoding.EncodeToString(
				(elliptic.Marshal(c, x, y))),
			hex.EncodeToString(priv))
	}

}
