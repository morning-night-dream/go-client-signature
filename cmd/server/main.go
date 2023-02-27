package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"go-client-signature/api"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
)

func main() {
	router := chi.NewRouter()

	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5173"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	handler := api.HandlerWithOptions(NewAPI(), api.ChiServerOptions{
		BaseRouter:  router,
		Middlewares: []api.MiddlewareFunc{},
	})

	srv := &http.Server{
		Addr:              ":5555",
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
	}

	log.Printf("Listening on http://localhost%s", srv.Addr)

	srv.ListenAndServe()
}

type API struct {
	lock       sync.Mutex
	signatures map[string]*rsa.PublicKey
}

func NewAPI() *API {
	return &API{
		signatures: make(map[string]*rsa.PublicKey),
	}
}

// (POST /key/go)
func (ap *API) KeyGo(w http.ResponseWriter, r *http.Request) {
	ap.lock.Lock()
	defer ap.lock.Unlock()

	var body api.KeyGoJSONBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	pub, err := base64.StdEncoding.DecodeString(body.PublicKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var key *rsa.PublicKey
	if err := json.Unmarshal(pub, &key); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sid := uuid.NewString()

	ap.signatures[sid] = key

	http.SetCookie(w, &http.Cookie{
		Name:     "signature",
		Value:    sid,
		Expires:  time.Now().Add(168 * time.Hour),
		Secure:   false,
		HttpOnly: true,
		Path:     "/",
	})

	w.Write([]byte("OK"))
}

// (POST /key/js)
func (ap *API) KeyJS(w http.ResponseWriter, r *http.Request) {
	ap.lock.Lock()
	defer ap.lock.Unlock()

	var body api.KeyGoJSONBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	pubkey, err := base64.RawStdEncoding.DecodeString(body.PublicKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	pub, err := x509.ParsePKIXPublicKey(pubkey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sid := uuid.NewString()

	ap.signatures[sid] = key

	http.SetCookie(w, &http.Cookie{
		Name:     "signature",
		Value:    sid,
		Expires:  time.Now().Add(168 * time.Hour),
		Secure:   false,
		HttpOnly: true,
		Path:     "/",
	})

	w.Write([]byte("OK"))
}

// (GET /sign)
func (ap *API) Sign(w http.ResponseWriter, r *http.Request, params api.SignParams) {
	ap.lock.Lock()
	defer ap.lock.Unlock()

	sid, err := r.Cookie("signature")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	key, ok := ap.signatures[sid.Value]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h := crypto.Hash.New(crypto.SHA256)
	h.Write([]byte(params.Code))
	hashed := h.Sum(nil)

	sig, err := base64.StdEncoding.DecodeString(params.Signature)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed, sig); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Write([]byte("OK"))
}
