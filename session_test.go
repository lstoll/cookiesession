package cookiesession

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sessionpb "github.com/lstoll/cookiesession/internal/proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func (t *testSession) GetKv() map[string]string {
	return t.KV
}

// type kvSession interface {
// 	SetValue(ctx context.Context, k, v string)
// 	GetValue(context.Context) (string, bool)
// 	Save(context.Context, )
// }

// type goKVSession struct {
// 	mgr *Manager[testSession, *testSession]
// }

// func (g goKVSession) SetValue(ctx context.Context, k, v string) {
// 	sess := g.mgr.Get(ctx)
// 	if sess.KV == nil {
// 		sess.KV =
// 	}
// }

// type protoKVSession struct {
// 	mgr *Manager[sessionpb.Session, *sessionpb.Session]
// }

func TestCookieSession(t *testing.T) {

	mgr, err := New[testSession]("test-sess", newHandle(t), Options{})
	if err != nil {
		t.Fatal(err)
	}

	protoMgr, err := New[sessionpb.Session]("proto-sess", newHandle(t), Options{})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		Name     string
		Wrap     func(http.Handler) http.Handler
		SetValue func(ctx context.Context, k, v string)
		GetValue func(ctx context.Context, k string) (string, bool)
		Clear    func(context.Context)
	}{
		{
			Name: "Go, JSON type",
			Wrap: mgr.Wrap,
			SetValue: func(ctx context.Context, k, v string) {
				sess := mgr.Get(ctx)

				if sess.KV == nil {
					sess.KV = make(map[string]string)
				}
				sess.KV[k] = v

				mgr.Save(ctx, sess)
			},
			GetValue: func(ctx context.Context, k string) (string, bool) {
				sess := mgr.Get(ctx)
				v, ok := sess.KV[k]
				return v, ok
			},
			Clear: func(ctx context.Context) {
				mgr.Delete(ctx)
			},
		},
		{
			Name: "Go, Proto type",
			Wrap: protoMgr.Wrap,
			SetValue: func(ctx context.Context, k, v string) {
				sess := protoMgr.Get(ctx)

				if sess.Kv == nil {
					sess.Kv = make(map[string]string)
				}
				sess.Kv[k] = v

				protoMgr.Save(ctx, sess)
			},
			GetValue: func(ctx context.Context, k string) (string, bool) {
				sess := protoMgr.Get(ctx)
				v, ok := sess.Kv[k]
				return v, ok
			},
			Clear: func(ctx context.Context) {
				protoMgr.Delete(ctx)
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			mux := http.NewServeMux()

			mux.HandleFunc("GET /set", func(w http.ResponseWriter, req *http.Request) {
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

				tc.SetValue(req.Context(), key, value)
			})

			mux.HandleFunc("GET /get", func(w http.ResponseWriter, req *http.Request) {
				key := req.URL.Query().Get("key")
				if key == "" {
					t.Fatal("query with no key")
				}

				value, ok := tc.GetValue(req.Context(), key)
				if !ok {
					t.Logf("key %s has no value", key)
					http.Error(w, fmt.Sprintf("key %s has no value", key), http.StatusInternalServerError)
					return
				}

				_, _ = w.Write([]byte(value))
			})

			mux.HandleFunc("GET /clear", func(_ http.ResponseWriter, req *http.Request) {
				tc.Clear(req.Context())
			})

			svr := httptest.NewServer(tc.Wrap(mux))
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

		})
	}
}

func TestSerialization(t *testing.T) {
	mgr, err := New[testSession]("test-sess", newHandle(t), Options{})
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

	protoMgr, err := New[sessionpb.Session]("proto-sess", newHandle(t), Options{})
	if err != nil {
		t.Fatal(err)
	}

	enc, err = protoMgr.serializeData(&sessionpb.Session{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = protoMgr.deserializeData(enc)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeadlineSession(t *testing.T) {
	mgr, err := New[testDeadlineSession]("test-sess", newHandle(t), Options{})
	if err != nil {
		t.Fatal(err)
	}

	unexpired := &session[testDeadlineSession, *testDeadlineSession]{
		data: &testDeadlineSession{
			EndDate: time.Now().Add(5 * time.Minute),
		},
		persist: true,
	}

	got, loaded, delete := roundtripSession(t, mgr, unexpired)
	if got == nil || loaded == false || delete == true {
		t.Errorf("want session, loaded, not marked for delete, got: %v loaded: %t delete: %t", got, loaded, delete)
	}

	expired := &session[testDeadlineSession, *testDeadlineSession]{
		data: &testDeadlineSession{
			EndDate: time.Now().Add(-5 * time.Minute),
		},
		persist: true,
	}

	got, loaded, delete = roundtripSession(t, mgr, expired)
	if got != nil || loaded == true || delete == false {
		t.Errorf("want no session, unloaded, and marked for delete, got: %v loaded: %t delete: %t", got, loaded, delete)
	}

	protoMgr, err := New[sessionpb.SessionWithDeadline]("proto-sess", newHandle(t), Options{})
	if err != nil {
		t.Fatal(err)
	}

	protoUnexpired := &session[sessionpb.SessionWithDeadline, *sessionpb.SessionWithDeadline]{
		data: &sessionpb.SessionWithDeadline{
			NotAfter: timestamppb.New(time.Now().Add(5 * time.Minute)),
		},
		persist: true,
	}

	protoGot, protoLoaded, protoDelete := roundtripSession(t, protoMgr, protoUnexpired)
	if protoGot == nil || protoLoaded == false || protoDelete == true {
		t.Errorf("want proto session, loaded, not marked for delete, got: %v loaded: %t delete: %t", protoGot, protoLoaded, protoDelete)
	}

	protoExpired := &session[sessionpb.SessionWithDeadline, *sessionpb.SessionWithDeadline]{
		data: &sessionpb.SessionWithDeadline{
			NotAfter: timestamppb.New(time.Now().Add(-5 * time.Minute)),
		},
		persist: true,
	}

	protoGot, protoLoaded, protoDelete = roundtripSession(t, protoMgr, protoExpired)
	if got != nil || loaded == true || delete == false {
		t.Errorf("want no proto session, unloaded, and marked for delete, got: %v loaded: %t delete: %t", protoGot, protoLoaded, protoDelete)
	}
}

// roundtripSession writes and then loads the session, returning the load result
func roundtripSession[T any, PtrT interface{ *T }](t testing.TB, mgr *Manager[T, PtrT], sess *session[T, PtrT]) (_ PtrT, loaded, delete bool) {
	rec := httptest.NewRecorder()

	if err := mgr.writeSession(rec, sess); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	got, loaded, delete, err := mgr.loadSession(req)
	if err != nil {
		t.Fatal(err)
	}

	return got, loaded, delete
}

func newHandle(t testing.TB) KeysetHandleFunc {
	h, err := keyset.NewHandle(aead.AES128GCMSIVKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	return StaticKeysetHandle(h)
}

type testDeadlineSession struct {
	EndDate time.Time `json:"end_date"`
}

func (testDeadlineSession) SessionName() string {
	return "test-with-deadline"
}

var _ DeadlineSession = (*testDeadlineSession)(nil)

func (t *testDeadlineSession) NotAfter() time.Time {
	return t.EndDate
}
