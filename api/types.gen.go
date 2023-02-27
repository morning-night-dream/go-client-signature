// Package api provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.12.4 DO NOT EDIT.
package api

// KeyGoJSONBody defines parameters for KeyGo.
type KeyGoJSONBody struct {
	// PublicKey 公開鍵
	PublicKey string `json:"publicKey"`
}

// KeyJSJSONBody defines parameters for KeyJS.
type KeyJSJSONBody struct {
	// PublicKey 公開鍵
	PublicKey string `json:"publicKey"`
}

// SignParams defines parameters for Sign.
type SignParams struct {
	// Code 署名付きコード
	Code string `form:"code" json:"code"`

	// Signature 署名
	Signature string `form:"signature" json:"signature"`
}

// KeyGoJSONRequestBody defines body for KeyGo for application/json ContentType.
type KeyGoJSONRequestBody KeyGoJSONBody

// KeyJSJSONRequestBody defines body for KeyJS for application/json ContentType.
type KeyJSJSONRequestBody KeyJSJSONBody