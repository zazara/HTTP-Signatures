package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"time"
)

func HttpSignaturesFormat(verb, path, host string) string {
	date := time.Now().Format("02 Jan 2006 15:04:05")
	return fmt.Sprintf("(request-target): %s %s\nhost: %s\ndate: %s GMT", verb, path, host, date)
}

type keyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

func main() {
	url := "https://www.yahoo.com"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer access-token")

	dump, _ := httputil.DumpRequestOut(req, true)
	fmt.Printf("%s", dump)
	host := "mstdn.jp"
	verb := "get"
	path := "/users/lain/inbox"
	date := time.Now().Format("02 Jan 2006 15:04:05")
	str := fmt.Sprintf("(request-target): %s %s\nhost: %s\ndate: %s GMT", verb, path, host, date)
	fmt.Println(str)

	// key, _ := openssl.GenerateRSAKey(1024)
	// pem, _ := key.MarshalPKCS1PrivateKeyPEM()
	// fmt.Println(string(pem))

	// cert, _ := openssl.LoadCertificateFromPEM(pem)
	// pub, _ := cert.PublicKey()
	// pub_pem, _ := pub.MarshalPKIXPublicKeyPEM()
	// fmt.Println(string(pub_pem))

	rsaPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPublicKey := rsaPrivateKey.Public()
	fmt.Println(rsaPublicKey)
	derPrivateKey, _ := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	privbyte := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derPrivateKey})
	fmt.Println(string(privbyte))
	if err := ioutil.WriteFile("private.pem", privbyte, os.ModePerm); err != nil {
		panic(err)
	}

	var derPublicKey []byte
	if rsaPublicKeyPointer, ok := rsaPublicKey.(*rsa.PublicKey); ok {
		derPublicKey = x509.MarshalPKCS1PublicKey(rsaPublicKeyPointer)
	}
	pubbyte := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derPublicKey})
	fmt.Println(string(pubbyte))
	if err := ioutil.WriteFile("public.pem", pubbyte, os.ModePerm); err != nil {
		panic(err)
	}
}
