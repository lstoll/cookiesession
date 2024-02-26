package cookiesession

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testSession struct {
	KV map[string]string `json:"kv"`
}

func (testSession) SessionName() string {
	return "test-session"
}

func (t *testSession) Init() {
	t.KV = map[string]string{}
}

func TestCookieSession(t *testing.T) {

	mux := http.NewServeMux()

	mgr, err := New[testSession](newStaticKeys(t, 1), Options{})
	if err != nil {
		t.Fatal(err)
	}

	mux.HandleFunc("GET /set", func(w http.ResponseWriter, req *http.Request) {
		sess, _ := mgr.Get(req.Context())

		key := req.URL.Query().Get("key")
		if key == "" {
			http.Error(w, "query with no key", http.StatusInternalServerError)
			return
		}

		value := req.URL.Query().Get("value")
		if key == "" {
			t.Logf("query with no value")
			http.Error(w, "query with no value", http.StatusInternalServerError)
			return
		}

		sess.KV[key] = value

		mgr.Save(req.Context(), sess)

		t.Logf("set: %#v", sess)
	})

	mux.HandleFunc("GET /get", func(w http.ResponseWriter, req *http.Request) {
		key := req.URL.Query().Get("key")
		if key == "" {
			t.Fatal("query with no key")
		}

		sess, _ := mgr.Get(req.Context())
		t.Logf("get: %#v", sess)

		value, ok := sess.KV[key]
		if !ok {
			t.Logf("key %s has no value", key)
			http.Error(w, fmt.Sprintf("key %s has no value", key), http.StatusInternalServerError)
			return
		}

		_, _ = w.Write([]byte(value))
	})

	mux.HandleFunc("GET /clear", func(_ http.ResponseWriter, req *http.Request) {
		mgr.Delete(req.Context())
	})

	svr := httptest.NewServer(mgr.Wrap(mux))
	t.Cleanup(svr.Close)

	resp, err := http.Get(svr.URL + "/set?key=test1&value=value1")
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set returned non-200: %d", resp.StatusCode)
	}

	cookies := resp.Cookies()

	req, err := http.NewRequest(http.MethodGet, svr.URL+"/get?key=test1", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set returned non-200: %d", resp.StatusCode)
	}

	if body, err := io.ReadAll(resp.Body); err != nil && string(body) != "value1" {
		t.Fatalf("wanted response body value1, got %s (err: %v)", string(body), err)
	}

	// clear it, and make sure it doesn't work
	_, err = http.Get(svr.URL + "/clear")
	if err != nil {
		t.Fatal(err)
	}

	// clear it, and make sure it doesn't work
	resp, err = http.Get(svr.URL + "/get?key=test1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusOK {
		t.Errorf("getting after clear should error")
	}
}

func TestSerialization(t *testing.T) {
	ks := newStaticKeys(t, 5)

	mgr, err := New[testSession](ks, Options{})
	if err != nil {
		t.Fatal(err)
	}

	enc, err := mgr.serializeData(&testSession{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = mgr.deserializeData(enc)
	if err != nil {
		t.Fatal(err)
	}

	// TODO - test with enc with old key
	// TODO - test with dec with unknown key
}

// newStaticKeys returns a new StaticKeys with len keys, the first being for
// encryption and the rest being for decryption
func newStaticKeys(t testing.TB, len int) *StaticKeys {
	var keys [][]byte

	for range 5 {
		k := make([]byte, KeySizeAES128)
		if _, err := io.ReadFull(rand.Reader, k); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}

	//	start in the default state
	return &StaticKeys{
		Encryption: keys[0],
		Decryption: keys[1:],
	}
}
