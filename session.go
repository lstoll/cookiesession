package cookiesession

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// cookieMagic prefixes the data, to give us the option in future to evolve the
// serialization without breaking existing data.
const cookieMagic = "EC1."

type sessCtxKey struct{ sessName string }

// type SessionData any

// SessionDataPtr is the interface that a session must implement on its pointer
// type.
type SessionDataPtr[T any] interface {
	*T
	// SessionName returns the cookie name that this session should be persisted
	// under.
	SessionName() string
}

// InitableSession is an optional interface a session data type can implement.
// If it does, the Init() method will be called if a new session is created.
type InitableSession interface {
	Init()
}

// DeadlineSession is an optional interface a session data type can implement.
// If it does, the session will not be considered valid after this date and will
// be discarded if it's seen. This is useful because the cookie max age only
// asks the browser to enforce that age on each save, the user can interfere
// with it. If they do, the session will be considered valid until it's
// encryption key is no longer used. Setting a deadline can avoid this.
type DeadlineSession interface {
	// NotAfter is a time we will no longer consider this session valid.
	NotAfter() time.Time
}

// session is the type we pass around, to track things internally.
type session[T any, PtrT SessionDataPtr[T]] struct {
	data PtrT
	// persist indicates that we should persist this session at the end of the
	// request. it has priority over delete
	persist bool
	// delete indicates we should delete the session at the end of the request.
	delete bool
}

// Manager is used to wrap a http Handler to manage fetching/setting sessions
// during the HTTP request lifecycle, as well as retrieving sessions inside a
// handler.
//
// The session data type will be JSON serialized, compressed, and AES-GCM
// encrypted. This must fit within 4kb post-processing to fit within a cookie,
// no automatic sharding is supported.
//
// It should be created via the New function.
type Manager[T any, PtrT SessionDataPtr[T]] struct {
	keys Keys
	opts Options
}

// Options are used to customize the Manager. Most options pass through to the
// Cookie the session is persisted in,
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies is a good reference
// for these.
type Options struct {
	// Path corresponds to the HTTP Cookie Path attribute. Optional.
	Path string
	// MaxAge sets the MaxAge atrribute for the HTTP Cookie. The same format as
	// *http.Cookie is used (https://pkg.go.dev/net/http#Cookie), except as a
	// duration.. Note that a cookie is set each time the session is saved, so
	// this is not an absolute time from the session's creation. Optional.
	MaxAge time.Duration
	// Insecure flags the cookie to be sent over non-https requests. It's the
	// inverse of the HTTP cookie `Secure` attribute. Optional.
	Insecure bool
	// Domain corresponds to the HTTP Cookie Domain. Optional.
	Domain string
	// SameSite corresponds to the HTTP Cookie SameSite attribute. Optional.
	SameSite http.SameSite

	// ErrorHandler is called if any errors occur during session management in
	// the handler wrapper. If not set, a basic default error message is
	// rendered. The error passed here should not be rendered to the user.
	ErrorHandler func(error, http.ResponseWriter, *http.Request)
	// FailOnSessionLoadError indicates that if there is an error loading the
	// session (e.g bad cookie data, invalid encryption key etc.) we should
	// return an error to the user, rather than just instantiating a new
	// session.
	FailOnSessionLoadError bool
}

func (o *Options) newCookie(name, value string) *http.Cookie {
	return &http.Cookie{
		Name:  name,
		Value: value,

		Path:   o.Path,
		Domain: o.Domain,

		MaxAge:   int(o.MaxAge.Seconds()),
		Secure:   !o.Insecure,
		HttpOnly: true, // we should be the only consumer anyway
		SameSite: o.SameSite,
	}
}

// Keys is used to retrieve encryption/decryption keys as needed. This enables
// the dynamic fetching/rotation of keys, which is reccomended to ensure regular
// rotation of secrets. The keys must be valid AES key sizes.
type Keys interface {
	// EncryptionKey returns the current encryption key. This will also be
	// used for decryption.
	EncryptionKey() []byte
	// DecryptionKeys returns a list of additional keys that can be considered
	// for decryption. This is used to prevent invalidating current sessions
	// when the encryption key is rotated. The current encryption key does not
	// need to be returned in this list.
	DecryptionKeys() [][]byte
}

// New create a new instance of the session Manager. It should be instantiated
// with a non-pointer type to the data structure that represents the session,
// e.g `New[mySessionStruct](...)`.
func New[T any, PtrT SessionDataPtr[T]](keys Keys, opts Options) (*Manager[T, PtrT], error) {
	for _, k := range append(keys.DecryptionKeys(), keys.EncryptionKey()) {
		if err := validateKeySize(k); err != nil {
			return nil, fmt.Errorf("invalid key size: %w", err)
		}
	}

	if opts.ErrorHandler == nil {
		opts.ErrorHandler = defaultErrorHandler
	}
	return &Manager[T, PtrT]{
		keys: keys,
		opts: opts,
	}, nil
}

// Wrap should be called with a HTTP handler that needs to have sessions inside
// it managed. Sessions will not be accessible outside of this wrapper. The
// session will be persisted on the first call to write/writeheader, it will no
// longer be modifiable after that.
func (m *Manager[T, PtrT]) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sd, loaded, delete, err := m.loadSession(r)
		if err != nil && m.opts.FailOnSessionLoadError {
			m.opts.ErrorHandler(err, w, r)
			return
		}
		if !loaded {
			// either failed or loaded no cookie, init a new session.
			sd = m.newSessData()
		}

		sess := &session[T, PtrT]{
			data:   sd,
			delete: delete,
		}

		r = r.WithContext(context.WithValue(r.Context(), sessCtxKey{sessName: sess.data.SessionName()}, sess))
		hw := &hookRW{
			ResponseWriter: w,
			hook: func(w http.ResponseWriter) bool {
				if err := m.writeSession(w, sess); err != nil {
					m.opts.ErrorHandler(err, w, r)
					return false
				}
				return true
			},
		}

		next.ServeHTTP(hw, r)

		// if the handler doesn't write anything, make sure we fire the hook
		// anyway.
		hw.hookOnce.Do(func() {
			hw.hook(hw.ResponseWriter)
		})
	})
}

// Get will retrieve the session from the HTTP request context. If a session
// exists, it will be returned. If a session does not exist, a new session
// object will be returned.  If a deletion has already been flagged in this
// request, this will create a new session. If updated, Save should be called.
//
// If this is called inside a handler that was not Wrap'd by this manager, it
// will panic.
func (m *Manager[T, PtrT]) Get(ctx context.Context) PtrT {
	sess, ok := ctx.Value(sessCtxKey{sessName: PtrT(new(T)).SessionName()}).(*session[T, PtrT])
	if !ok {
		panic("context contained no or invalid session")
	}
	return sess.data
}

// Save saves a modified session object. It is safe to call this repeatedly in a
// request.
func (m *Manager[T, PtrT]) Save(ctx context.Context, updated PtrT) {
	sess, ok := ctx.Value(sessCtxKey{PtrT(new(T)).SessionName()}).(*session[T, PtrT])
	if !ok {
		panic("context contained no or invalid session")
	}
	sess.data = updated
	sess.delete = false
	sess.persist = true
}

// Delete will mark the session to be deleted at the end of the request. It is
// safe to subsequently create a new session  after this.
func (m *Manager[T, PtrT]) Delete(ctx context.Context) {
	sess, ok := ctx.Value(sessCtxKey{PtrT(new(T)).SessionName()}).(*session[T, PtrT])
	if !ok {
		panic("context contained no or invalid session")
	}
	sess.persist = false
	sess.delete = true
	// wipe the data here, in case there's a subsequent get
	sess.data = m.newSessData()
}

func (m *Manager[T, PtrT]) serializeData(data PtrT) (string, error) {
	var buf bytes.Buffer

	jw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(jw).Encode(data); err != nil {
		return "", fmt.Errorf("encoding session data: %w", err)
	}
	if err := jw.Close(); err != nil {
		return "", fmt.Errorf("closing gzip writer: %w", err)
	}

	ek := m.keys.EncryptionKey()

	context := map[string]string{
		"magic":        cookieMagic,
		"session-name": data.SessionName(),
	}

	ed, err := encryptData(ek, buf.Bytes(), context)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	return cookieMagic + base64.RawURLEncoding.EncodeToString(ed), nil
}

func (m *Manager[T, PtrT]) deserializeData(data string) (PtrT, error) {
	if !strings.HasPrefix(data, cookieMagic) {
		return nil, fmt.Errorf("invalid data, missing magic")
	}

	ret := PtrT(new(T))

	ek := m.keys.EncryptionKey()
	decKs := m.keys.DecryptionKeys()

	context := map[string]string{
		"magic":        cookieMagic,
		"session-name": ret.SessionName(),
	}

	db, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(data, cookieMagic))
	if err != nil {
		return nil, fmt.Errorf("base64 decoding data: %w", err)
	}

	var plaintext []byte
	for _, dk := range append([][]byte{ek}, decKs...) {
		pt, err := decryptData(dk, db, context)
		if err != nil {
			continue
		}
		plaintext = pt
	}
	if plaintext == nil {
		return nil, fmt.Errorf("failed to decrypt data")
	}

	gr, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	if err := json.NewDecoder(gr).Decode(&ret); err != nil {
		return nil, fmt.Errorf("decoding json: %w", err)
	}
	if err := gr.Close(); err != nil {
		return nil, fmt.Errorf("closing gzip reader: %w", err)
	}

	return ret, nil
}

func (m *Manager[T, PtrT]) loadSession(r *http.Request) (_ PtrT, loaded, delete bool, _ error) {
	sessName := PtrT(new(T)).SessionName()

	cookie, err := r.Cookie(sessName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return nil, false, false, nil
		}
		return nil, false, true, fmt.Errorf("getting cookie %s: %w", sessName, err)
	}

	sd, err := m.deserializeData(cookie.Value)
	if err != nil {
		return nil, false, true, fmt.Errorf("deserializing cookie value: %w", err)
	}

	if ds, ok := any(sd).(DeadlineSession); ok {
		if time.Now().After(ds.NotAfter()) {
			return nil, false, true, nil
		}
	}

	return sd, true, false, nil
}

func (m *Manager[T, PtrT]) writeSession(w http.ResponseWriter, sess *session[T, PtrT]) error {
	if sess.persist {
		ser, err := m.serializeData(sess.data)
		if err != nil {
			return fmt.Errorf("serializing data")
		}
		if len(ser) > 4096 {
			return fmt.Errorf("data size %d beyond max of 4096", len(ser))
		}
		c := m.opts.newCookie(sess.data.SessionName(), ser)
		http.SetCookie(w, c)
	} else if sess.delete {
		c := m.opts.newCookie(sess.data.SessionName(), "")
		c.MaxAge = -1
		http.SetCookie(w, c)
	}
	return nil
}

func (m *Manager[T, PtrT]) newSessData() PtrT {
	sd := PtrT(new(T))
	if is, ok := any(sd).(InitableSession); ok {
		is.Init()
	}
	return sd
}

// hookRW can be used to trigger an action before the response writing starts,
// in our case saving the session. It will only be called once
type hookRW struct {
	http.ResponseWriter
	// hook is called with the responsewriter. it returns a bool indicating if
	// we should continue with what we were doing, or if we should interupt the
	// response because it handled it.
	hook     func(http.ResponseWriter) bool
	hookOnce sync.Once
}

func (h *hookRW) Write(b []byte) (int, error) {
	write := true
	h.hookOnce.Do(func() {
		write = h.hook(h.ResponseWriter)
	})
	if !write {
		return 0, errors.New("request interrupted by hook")
	}
	return h.ResponseWriter.Write(b)
}

func (h *hookRW) WriteHeader(statusCode int) {
	write := true
	h.hookOnce.Do(func() {
		write = h.hook(h.ResponseWriter)
	})
	if write {
		h.ResponseWriter.WriteHeader(statusCode)
	}
}

func defaultErrorHandler(err error, w http.ResponseWriter, r *http.Request) {
	slog.ErrorContext(r.Context(), "error occured in cookie session wrapper", slog.String("err", err.Error()))
	http.Error(w, "Internal Error", http.StatusInternalServerError)
}
