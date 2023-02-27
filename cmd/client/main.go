package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go-client-signature/api"
	"log"
	"net/http"
)

func main() {
	url := "http://localhost:5555"

	client, err := api.NewClient(url)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// publickey
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	pub := priv.Public()

	bytes, err := json.Marshal(pub)
	if err != nil {
		panic(err)
	}

	pubstr := base64.StdEncoding.EncodeToString(bytes)

	body := api.KeyGoJSONRequestBody{
		PublicKey: pubstr,
	}

	res, err := client.KeyGo(ctx, body)
	if err != nil {
		panic(err)
	}

	client.Client = &http.Client{
		Transport: NewCookieTransport(res.Cookies()),
	}

	// sign
	code := "reichankawaii"

	h := crypto.Hash.New(crypto.SHA256)
	h.Write([]byte(code))
	hashed := h.Sum(nil)

	signed, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed)
	if err != nil {
		panic(err)
	}

	signature := base64.StdEncoding.EncodeToString(signed)

	res, err = client.Sign(ctx, &api.SignParams{
		Code:      code,
		Signature: signature,
	})
	if err != nil {
		panic(err)
	}

	log.Printf("%+v", res)
}

type CookieTransport struct {
	Cookies   []*http.Cookie
	Transport http.RoundTripper
}

func NewCookieTransport(
	cookies []*http.Cookie,
) *CookieTransport {
	return &CookieTransport{
		Cookies:   cookies,
		Transport: http.DefaultTransport,
	}
}

func (ct *CookieTransport) transport() http.RoundTripper {
	return ct.Transport
}

func (ct *CookieTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for _, cookie := range ct.Cookies {
		fmt.Printf("cookie: %+v\n", cookie)
		req.AddCookie(cookie)
	}

	resp, err := ct.transport().RoundTrip(req)
	if err != nil {
		return nil, err
	}

	return resp, err
}
