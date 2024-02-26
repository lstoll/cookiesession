# cookiesession

[![Go Reference](https://pkg.go.dev/badge/github.com/lstoll/cookiesession.svg)](https://pkg.go.dev/github.com/lstoll/cookiesession)

Status: **in development**

cookiesession is a Go library for easy, cookie-based sessions. It provides a typed interface for getting and setting the session in HTTP handlers, with minimal fuss. Cookies are encrypted and authenticated by default.

### Example

```

// sessionData is the type for our session. It is JSON serialized, so we tag it
// appropriately.
type sessionData struct {
	Name string `json:"name"`
}

// SessionName assigns this session type a unique name, so it can interact with
// other sessions. Multiple Managers in use is possible.
func (sessionData) SessionName() string {
	return "example"
}

// derive a key from a passphrase
keys, _ := KeysFromPassphrases("my-cookie-encryption-passphrase")

// create the manager for our session type
csmgr, _ := New[sessionData](keys, Options{
    Path:   "/",
    MaxAge: 60 * time.Minute,
})

mux := http.NewServeMux()

mux.HandleFunc("POST /set", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
    sess, _ := csmgr.Get(r.Context())

    sess.Name = r.FormValue("name")

    csmgr.Save(r.Context(), sess)
}))

mux.HandleFunc("GET /read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    sess, _ := csmgr.Get(r.Context())

    w.Write([]byte(sess.Name))
}))

```
