package main

import (
	"bytes"
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
	"os"
	"strings"
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
	Actor string `json:"actor"`
	Type  string `json:"type`
}

func newSignRequest(host, verb, path string, body interface{}) *http.Request {
	bodyJSON, _ := json.Marshal(body)
	req, _ := http.NewRequest(strings.ToUpper(verb), "https://imastodon.net/users/Teru/inbox", bytes.NewBuffer(bodyJSON))
	date := time.Now().Format("02 Jan 2006 15:04:05")
	header_str := fmt.Sprintf("(request-target): %s %s\nhost: %s\ndate: %s GMT", verb, path, host, date)
	ran := rand.Reader
	rsaPrivateKey, _ := rsa.GenerateKey(ran, 2048)
	hasher := sha256.New()
	hasher.Write([]byte(header_str))
	tokenHash := hasher.Sum(nil)
	signed_byte, _ := rsa.SignPSS(ran, rsaPrivateKey, crypto.SHA256, tokenHash, nil)

	encoded_str := base64.StdEncoding.EncodeToString(signed_byte)

	signed_header := fmt.Sprintf("keyId=\"%s\",headers=\"(request-target) host date\",signature=\"%s\"", "https://actub.hatawaku.xyz/users/test#main-key", encoded_str)
	req.Header.Set("Signature", signed_header)
	req.Header.Set("Content-Type", "application/activity+json")
	return req
}

type icon struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type publicKey struct {
	Id           string `json:"id"`
	Owner        string `json:"owner"`
	PublicKeyPem string `json:"publicKeyPem"`
}

type user struct {
	Context           string    `json:"@context"`
	Type              string    `json:"type"`
	Id                string    `json:"id"`
	Name              string    `json:"name"`
	PreferredUsername string    `json:"preferredUsername"`
	Summary           string    `json:"summary"`
	Inbox             string    `json:"inbox"`
	Outbox            string    `json:"outbox"`
	Icon              icon      `json:"icon"`
	PublicKey         publicKey `json:"publicKey"`
}

func newUserStruct(userId string) user {
	siteURL := "https://actub.hatawaku.xyz/"
	userURL := siteURL + "users/" + userId
	newUser := user{}
	newUser.Context = "https://www.w3.org/ns/activitystreams"
	newUser.Type = "Person"
	newUser.Id = userURL
	newUser.Name = userId
	newUser.PreferredUsername = userId
	newUser.Summary = userId + "'s summary"
	newUser.Inbox = userURL + "/inbox"
	newUser.Outbox = userURL + "/outbox"
	newIcon := icon{Type: "Image", URL: "https://actub.hatawaku.xyz/media/test"}
	newUser.Icon = newIcon
	newPublicKey := publicKey{}
	newPublicKey.Id = siteURL + "users/" + userId + "#main-key"
	newPublicKey.Owner = siteURL + "users/" + userId
	newUser.PublicKey = newPublicKey
	return newUser
}

func main() {
	url := "https://mstdn.jp"
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Set("Authorization", "Bearer access-token")

	host := "mstdn.jp"
	verb := "get"
	path := "/users/lain/inbox"
	date := time.Now().Format("02 Jan 2006 15:04:05")
	header_str := fmt.Sprintf("(request-target): %s %s\nhost: %s\ndate: %s GMT", verb, path, host, date)
	ran := rand.Reader
	rsaPrivateKey, _ := rsa.GenerateKey(ran, 2048)
	rsaPublicKey := rsaPrivateKey.Public()
	derPrivateKey, _ := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	privbyte := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derPrivateKey})
	if err := ioutil.WriteFile("private.pem", privbyte, os.ModePerm); err != nil {
		panic(err)
	}

	var derPublicKey []byte
	if rsaPublicKeyPointer, ok := rsaPublicKey.(*rsa.PublicKey); ok {
		derPublicKey = x509.MarshalPKCS1PublicKey(rsaPublicKeyPointer)
	}
	pubbyte := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derPublicKey})
	if err := ioutil.WriteFile("public.pem", pubbyte, os.ModePerm); err != nil {
		panic(err)
	}

	hasher := sha256.New()
	hasher.Write([]byte(header_str))
	tokenHash := hasher.Sum(nil)

	signed_byte, _ := rsa.SignPSS(ran, rsaPrivateKey, crypto.SHA256, tokenHash, nil)

	encoded_str := base64.StdEncoding.EncodeToString(signed_byte)

	signed_header := fmt.Sprintf("keyId=\"%s\",headers=\"(request-target) host date\",signature=\"%s\"", "https://actub.hatawaku.xyz/users/test#main-key", encoded_str)
	req.Header.Set("Signature", signed_header)
	router := gin.Default()

	router.GET("/users/test", func(ctx *gin.Context) {
		person_json := newUserStruct("test")
		person_json.Summary = "Hi,This is my summary."
		ctx.JSON(200, person_json)
	})

	router.GET("/.well-known/host-meta", func(ctx *gin.Context) {
		file, err := ioutil.ReadFile("src/.well-known/host-meta")
		if err == nil {
			ctx.Data(200, "application/xml", file)
		}
	})
	type Link struct {
		Rel  string `json:"rel"`
		Type string `json:"type"`
		Href string `json:"href"`
	}
	type Finger struct {
		Subject string   `json:"subject"`
		Aliases []string `json:"aliases"`
		Links   []Link   `json:"links"`
	}
	router.GET("/.well-known/webfinger", func(ctx *gin.Context) {
		resource := ctx.Query("resource")
		splitedText := strings.Split(resource, "@")
		acct := strings.Split(splitedText[0], ":")
		userId := acct[1]

		webDomain := "actub.hatawaku.xyz"
		siteURL := "https://" + webDomain + "/"
		userURL := siteURL + "users/" + userId
		subject := "acct:" + userId + "@" + webDomain
		webfingerLink := Link{"http://webfinger.net/rel/profile-page", "text/html", userURL}
		activitypubLink := Link{"self", "application/activity+json", userURL}
		activityStreamLink := Link{"self", "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"", userURL}
		ostatusLink := Link{}
		ostatusLink.Rel = "http://ostatus.org/schema/1.0/subscribe"
		links := []Link{webfingerLink, activitypubLink, activityStreamLink, ostatusLink}
		webfingerJson := Finger{}
		webfingerJson.Subject = subject
		webfingerJson.Aliases = []string{userURL}
		webfingerJson.Links = links
		ctx.JSON(200, webfingerJson)

	})

	router.POST("/users/test/inbox", func(ctx *gin.Context) {
		contentType := ctx.GetHeader("Content-Type")
		fmt.Printf("contentType:%s\n", contentType)
		var followJSON followed
		if err := ctx.ShouldBindJSON(&followJSON); err != nil {
			fmt.Println("errorNAU")
			fmt.Errorf("%s\n", err)
		} else {

			fmt.Println("OKNAU")
			acceptJSON := accept{Context: "https://www.w3.org/ns/activitystreams", Type: "Accept", Actor: "https://actub.hatawaku.xyz/users/test", Object: followJSON}
			actor := followJSON.Actor
			fmt.Printf("actor:%s\n", actor)
			fmt.Printf("type:%s\n", followJSON.Type)
			signedReq := newSignRequest("mstdn.jp", "post", actor, acceptJSON)
			client := &http.Client{}
			resp, _ := client.Do(signedReq)
			fmt.Printf("reponse:%s\n", resp)
			// ctx.JSON(202, acceptJSON)
			ctx.Status(202)
			ctx.Data(202, "application/activity+json", []byte(""))
		}
	})

	router.Run(":5000")
}
