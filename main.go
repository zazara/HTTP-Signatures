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
	Context   string      `json:"@context"`
	Type      string      `json:"type"`
	Actor     string      `json:"actor"`
	Object    interface{} `json:"object"`
	PublicKey publicKey   `json:"publicKey`
}

type followed struct {
	Actor string `json:"actor"`
	Type  string `json:"type`
}

func newSignRequest(host, verb, path string, body interface{}) *http.Request {
	postUrl := "https://imastodon.net/users/rest/inbox"
	bodyJSON, _ := json.Marshal(body)
	req, _ := http.NewRequest(strings.ToUpper(verb), postUrl, bytes.NewBuffer(bodyJSON))
	date := time.Now().Format("02 Jan 2006 15:04:05")
	header_str := fmt.Sprintf("(request-target): %s %s\nhost: %s\ndate: %s GMT", verb, path, host, date)
	ran := rand.Reader
	block, _ := pem.Decode(readPem())
	rsaPrivateKey, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	hasher := sha256.New()
	hasher.Write([]byte(header_str))
	tokenHash := hasher.Sum(nil)
	signed_byte, _ := rsa.SignPSS(ran, rsaPrivateKey.(*rsa.PrivateKey), crypto.SHA256, tokenHash, nil)

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
	Context           []string  `json:"@context"`
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

type reply struct {
	Type         string `json:"type"`
	Id           string `json:"id"`
	Published    string `json:"published"`
	AttributedTo string `json:"attributedTo"`
	InReplyTo    string `json:"inReplyTo"`
	Content      string `json:"content"`
	To           string `json:"to"`
}

type create struct {
	Context string `json:"@context"`
	Type    string `json:"type"`
	Id      string `json:"id"`
	Actor   string `json:"actor"`
	Object  reply  `json:"object"`
}

func newUserStruct(userId string) user {
	siteURL := "https://actub.hatawaku.xyz/"
	userURL := siteURL + "users/" + userId
	newUser := user{}
	newUser.Context = []string{"https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"}
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

func readPem() []byte {
	f, err := os.Open("private.pem")
	if err != nil {
		fmt.Errorf("%s\n", err)
		return nil
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Errorf("%s\n", err)
		return nil
	}
	return b
}

func readPub() []byte {
	f, err := os.Open("public.pem")
	if err != nil {
		return nil
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	return b
}

func main() {
	router := gin.Default()

	/* router */
	router.GET("/users/test", func(ctx *gin.Context) {
		person_json := newUserStruct("test")
		person_json.Summary = "Hi,This is my summary."
		person_json.PublicKey.PublicKeyPem = string(readPub())
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
		f, _ := os.Open("create.json")
		defer f.Close()

		document, _ := ioutil.ReadAll(f)
		date := time.Now().Format("Mon, 02 Jan 2006 15:04:05 GMT")
		block, _ := pem.Decode(readPem())
		keypair, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
		signed_string := fmt.Sprintf("(request-target): post /inbox\nhost: imastodon.net\ndate: %s", date)
		fmt.Println(signed_string)
		hashedp := sha256.Sum256([]byte(signed_string))
		signature, _ := rsa.SignPKCS1v15(nil, keypair, crypto.SHA256, hashedp[:])
		header := `keyId="https://actub.hatawaku.xyz/users/test#main-key",headers="(request-target) host date",signature="` + base64.StdEncoding.EncodeToString(signature) + `"`
		req, _ := http.NewRequest("POST", "https://imastodon.net/inbox", bytes.NewBuffer(document))
		fmt.Println(header)
		fmt.Println(date)
		hashed := sha256.Sum256([]byte(signed_string))
		a, _ := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString(signature))
		erara := rsa.VerifyPKCS1v15(&keypair.PublicKey, crypto.SHA256, hashed[:], a)
		if erara != nil {
			fmt.Println(erara)
		} else {
			fmt.Println("verify")
		}
		req.Header.Set("Host", "imastodon.net")
		req.Header.Set("Date", date)
		req.Header.Set("Signature", header)
		client := &http.Client{}
		resp, era := client.Do(req)
		if era != nil {
			fmt.Println("era")
			fmt.Println(era)
		} else {
			defer resp.Body.Close()
			b, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				fmt.Println(string(b))
			} else {
				fmt.Print(err)
			}
		}
		ctx.Status(202)
	})

	router.Run(":5000")
}
