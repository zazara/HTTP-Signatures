package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

func HttpSignaturesFormat(verb, path, host string) string {
	date := time.Now().Format("02 Jan 2006 15:04:05")
	return fmt.Sprintf("(request-target): %s %s\nhost: %s\ndate: %s GMT", verb, path, host, date)
}

type keyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

type accept struct {
	Context string      `json:"@context"`
	Type    string      `json:"type"`
	Actor   string      `json:"actor"`
	Object  interface{} `json:"object"`
}

type followed struct {
	Acotr string `json:"actor"`
}

func main() {
	url := "https://mstdn.jp"
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Set("Authorization", "Bearer access-token")

	dump, _ := httputil.DumpRequestOut(req, true)
	fmt.Printf("%s", dump)
	host := "mstdn.jp"
	verb := "get"
	path := "/users/lain/inbox"
	date := time.Now().Format("02 Jan 2006 15:04:05")
	header_str := fmt.Sprintf("(request-target): %s %s\nhost: %s\ndate: %s GMT", verb, path, host, date)
	// fmt.Println(header_str)

	// key, _ := openssl.GenerateRSAKey(1024)
	// pem, _ := key.MarshalPKCS1PrivateKeyPEM()
	// fmt.Println(string(pem))

	// cert, _ := openssl.LoadCertificateFromPEM(pem)
	// pub, _ := cert.PublicKey()
	// pub_pem, _ := pub.MarshalPKIXPublicKeyPEM()
	// fmt.Println(string(pub_pem))
	ran := rand.Reader
	rsaPrivateKey, _ := rsa.GenerateKey(ran, 2048)
	rsaPublicKey := rsaPrivateKey.Public()
	// fmt.Println(rsaPublicKey)
	derPrivateKey, _ := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	privbyte := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derPrivateKey})
	// fmt.Println(string(privbyte))
	if err := ioutil.WriteFile("private.pem", privbyte, os.ModePerm); err != nil {
		panic(err)
	}

	var derPublicKey []byte
	if rsaPublicKeyPointer, ok := rsaPublicKey.(*rsa.PublicKey); ok {
		derPublicKey = x509.MarshalPKCS1PublicKey(rsaPublicKeyPointer)
	}
	pubbyte := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derPublicKey})
	// fmt.Println(string(pubbyte))
	if err := ioutil.WriteFile("public.pem", pubbyte, os.ModePerm); err != nil {
		panic(err)
	}

	hasher := sha256.New()
	hasher.Write([]byte(header_str))
	tokenHash := hasher.Sum(nil)

	//signed_byte, errors := rsaPrivateKey.Sign(ran, []byte(header_str), crypto.SHA256)
	signed_byte, errors := rsa.SignPSS(ran, rsaPrivateKey, crypto.SHA256, tokenHash, nil)
	fmt.Errorf("%s\n", errors)
	encoded_str := base64.StdEncoding.EncodeToString(signed_byte)

	signed_header := fmt.Sprintf("keyId=\"%s\",headers=\"(request-target) host date\",signature=\"%s\"", "https://actub.hatawaku.xyz/users/test#main-key", encoded_str)
	req.Header.Set("Signature", signed_header)
	t_dump, _ := httputil.DumpRequestOut(req, true)
	fmt.Println([]byte(header_str))
	fmt.Println(signed_byte)
	fmt.Println(encoded_str)
	fmt.Printf("%s", t_dump)
	//Signature: keyId="https://actub.hatawaku.xyz/users/test#main-key",headers="(request-target) host date",signature="Y2FiYW...IxNGRiZDk4ZA=="
	router := gin.Default()

	router.GET("/users/test", func(ctx *gin.Context) {
		file, err := ioutil.ReadFile("src/static/test.json")
		accept := ctx.GetHeader("accept")
		if accept == "application/activity+json" {
			var response interface{}
			if err == nil {
				json.Unmarshal(file, &response)
				fmt.Println(response)
			}
			ctx.Data(200, "application/activity+json", file)
		}
	})

	router.GET("/.well-known/host-meta", func(ctx *gin.Context) {
		file, err := ioutil.ReadFile("src/.well-known/host-meta")
		if err == nil {
			ctx.Data(200, "application/xml", file)
		}
	})

	router.POST("/users/inbox", func(ctx *gin.Context) {
		acceptType := ctx.GetHeader("accept")
		if acceptType != "application/activity+json" {

		} else {
			var followJSON interface{}
			if err := ctx.ShouldBindJSON(&followJSON); err != nil {
				acceptJSON := accept{Context: "https://www.w3.org/ns/activitystreams", Type: "Accept", Actor: "https://actub.hatawaku.xyz/users/test", Object: followJSON}

				ctx.JSON(200, acceptJSON)
			}
		}
	})

	//router.Run(":5000")
}
