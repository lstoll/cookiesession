package cookiesession

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"io"
	mathrand "math/rand/v2"
	"reflect"
	"sync/atomic"
	"testing"
)

func init() {
	gob.Register(map[string]any{})
}

func BenchmarkAESDecrypt(b *testing.B) {
	// this benchmark exists to make sure "just trying the listed keys" is fast
	// enough.

	var keys [][32]byte

	for range 100 {
		k := [32]byte{}
		if _, err := rand.Read(k[:]); err != nil {
			b.Fatal(err)
		}
		keys = append(keys, k)
	}

	randEncryptedData := func(b *testing.B, k [32]byte) (plaintext, nonce, sealed []byte) {
		plaintext = make([]byte, 4096) // 4kb, about max cookie size
		if _, err := rand.Read(plaintext); err != nil {
			b.Fatal(err)
		}

		block, err := aes.NewCipher(k[:])
		if err != nil {
			b.Fatal(err)
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			b.Fatal(err)
		}

		nonce = make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			panic(err.Error())
		}

		return plaintext, nonce, aesgcm.Seal(nil, nonce, plaintext, nil)
	}

	decryptData := func(b *testing.B, key [32]byte, nonce []byte, sealed []byte) ([]byte, bool) {
		block, err := aes.NewCipher(key[:])
		if err != nil {
			b.Fatal(err)
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			b.Fatal(err)
		}

		plaintext, err := aesgcm.Open(nil, nonce, sealed, nil)
		if err != nil {
			// It would be nice if there was a better way to match the specific
			// error reliably
			return nil, false
		}

		return plaintext, true
	}

	benchFn := func(encKey [32]byte, decKeys [][32]byte) func(b *testing.B) {
		return func(b *testing.B) {
			// encrypt with the first key
			orig, nonce, sealed := randEncryptedData(b, encKey)

			b.ResetTimer()

			for range b.N {
				var plaintext []byte
				for _, dk := range decKeys {
					p, ok := decryptData(b, dk, nonce, sealed)
					if !ok {
						continue
					}
					plaintext = p
				}
				if plaintext == nil {
					b.Fatal("decryption failed!")
				}

				b.StopTimer()
				if !bytes.Equal(orig, plaintext) {
					b.Fatal("decypted data differs.")
				}
				b.StartTimer()
			}

		}
	}

	b.Run("Single Key", benchFn(keys[0], [][32]byte{keys[0]}))
	b.Run("9 Previous Keys", benchFn(keys[9], keys[0:10]))
	b.Run("99 Previous Keys", benchFn(keys[99], keys[0:100]))
}

func BenchmarkSerialization(b *testing.B) {
	// this benchmark exists to make sure our desired serialization isn't too slow

	data := randCookieData(b)

	b.Run("gob", func(b *testing.B) {
		for range b.N {
			var buf bytes.Buffer

			if err := gob.NewEncoder(&buf).Encode(data); err != nil {
				b.Fatal(err)
			}

			b.SetBytes(int64(buf.Len()))

			var out map[string]any
			if err := gob.NewDecoder(&buf).Decode(&out); err != nil {
				b.Fatal(err)
			}

			b.StopTimer()
			if !reflect.DeepEqual(data, out) {
				b.Fatal("data differs")
			}
			b.StartTimer()
		}
	})

	b.Run("gzip gob", func(b *testing.B) {
		for range b.N {
			var buf bytes.Buffer

			w := gzip.NewWriter(&buf)
			sw := &sizeWriter{Writer: w}
			if err := gob.NewEncoder(sw).Encode(data); err != nil {
				b.Fatal(err)
			}
			if err := w.Close(); err != nil {
				b.Fatal(err)
			}

			// comparing the raw amout of gob we process, to equate with the
			// above
			b.SetBytes(sw.Len())

			var out map[string]any

			r, err := gzip.NewReader(&buf)
			if err != nil {
				b.Fatal(err)
			}
			if err := gob.NewDecoder(r).Decode(&out); err != nil {
				b.Fatal(err)
			}
			if err := r.Close(); err != nil {
				b.Fatal(err)
			}

			b.StopTimer()
			if !reflect.DeepEqual(data, out) {
				b.Fatal("data differs")
			}
			b.StartTimer()
		}
	})

	b.Run("JSON", func(b *testing.B) {
		for range b.N {
			var buf bytes.Buffer

			if err := json.NewEncoder(&buf).Encode(data); err != nil {
				b.Fatal(err)
			}

			b.SetBytes(int64(buf.Len()))

			var out map[string]any
			if err := json.NewDecoder(&buf).Decode(&out); err != nil {
				b.Fatal(err)
			}

			b.StopTimer()
			if !reflect.DeepEqual(data, out) {
				b.Fatal("data differs")
			}
			b.StartTimer()
		}
	})

	b.Run("gzip JSON", func(b *testing.B) {
		for range b.N {
			var buf bytes.Buffer

			w := gzip.NewWriter(&buf)
			sw := &sizeWriter{Writer: w}
			if err := json.NewEncoder(sw).Encode(data); err != nil {
				b.Fatal(err)
			}
			if err := w.Close(); err != nil {
				b.Fatal(err)
			}

			// comparing the raw amout of JSON we process, to equate with the
			// above
			b.SetBytes(sw.Len())

			var out map[string]any

			r, err := gzip.NewReader(&buf)
			if err != nil {
				b.Fatal(err)
			}
			if err := json.NewDecoder(r).Decode(&out); err != nil {
				b.Fatal(err)
			}
			if err := r.Close(); err != nil {
				b.Fatal(err)
			}

			b.StopTimer()
			if !reflect.DeepEqual(data, out) {
				b.Fatal("data differs")
			}
			b.StartTimer()
		}
	})
}

func BenchmarkCompressionRatio(b *testing.B) {
	// this exists to make sure compression for the data we're taking about
	// makes sense.

	data := randCookieData(b)

	for range b.N {
		var gbuf bytes.Buffer

		gw := gzip.NewWriter(&gbuf)
		gsw := sizeWriter{Writer: gw} // track the original data
		if err := gob.NewEncoder(&gsw).Encode(data); err != nil {
			b.Fatal(err)
		}
		if err := gw.Close(); err != nil {
			b.Fatal(err)
		}

		var jbuf bytes.Buffer

		jw := gzip.NewWriter(&jbuf)
		jsw := sizeWriter{Writer: jw} // track the original data
		if err := json.NewEncoder(&jsw).Encode(data); err != nil {
			b.Fatal(err)
		}
		if err := jw.Close(); err != nil {
			b.Fatal(err)
		}

		b.ReportMetric(float64(jsw.Len())/float64(gsw.Len()), "json/gob")
		b.ReportMetric(float64(jbuf.Len())/float64(gbuf.Len()), "jsongz/gobgz")
		b.ReportMetric(float64(jbuf.Len())/float64(jsw.Len()), "gz/json")
		b.ReportMetric(float64(gbuf.Len())/float64(gsw.Len()), "gz/gob")
	}
}

func BenchmarkEncryptionOverhead(b *testing.B) {
	// this test sees how much overhead encrypting the compressed data adds. we
	// only do this for JSON, more or less ruled gob out already.

	data := randCookieData(b)

	key := [32]byte{}
	if _, err := rand.Read(key[:]); err != nil {
		b.Fatal(err)
	}

	for range b.N {
		var jbuf bytes.Buffer

		jw := gzip.NewWriter(&jbuf)
		jsw := sizeWriter{Writer: jw} // track the original data
		if err := json.NewEncoder(&jsw).Encode(data); err != nil {
			b.Fatal(err)
		}
		if err := jw.Close(); err != nil {
			b.Fatal(err)
		}

		block, err := aes.NewCipher(key[:])
		if err != nil {
			b.Fatal(err)
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			b.Fatal(err)
		}

		nonce := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			panic(err.Error())
		}
		ed := append(nonce, aesgcm.Seal(nil, nonce, jbuf.Bytes(), nil)...)

		b.ReportMetric(float64(jbuf.Len())/float64(jsw.Len()), "gz/json")
		b.ReportMetric(float64(len(ed))/float64(jbuf.Len()), "enc/gz")
		b.ReportMetric(float64(len(ed))/float64(jsw.Len()), "encgz/json")
	}

}

var randChars = []rune(`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890`)

func randStr(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = randChars[mathrand.IntN(len(randChars))]
	}
	return string(b)
}

// randCookieData builds up a data structure that is roughly the max we could
// fit in a cookie (4kb of uncompressed JSON), for comparative benchmarks
func randCookieData(b *testing.B) map[string]any {
	data := map[string]any{}
	for range 10 {
		data[randStr(10)] = randStr(20)
		sm := map[string]any{}
		for range 10 {
			sm[randStr(10)] = randStr(20)
		}
		data[randStr(10)] = sm
	}

	jb, err := json.Marshal(data)
	if err != nil {
		b.Fatal(err)
	}

	origSize := len(jb)
	if origSize < 4000 || origSize > 4200 {
		b.Fatalf("expected random structure to be around 4096b in json, got: %d", origSize)
	}

	return data
}

// sizeWriter tracks the number of bytes written to a writer
type sizeWriter struct {
	io.Writer

	bytes int64
}

func (s *sizeWriter) Write(b []byte) (int, error) {
	atomic.AddInt64(&s.bytes, int64(len(b)))
	return s.Writer.Write(b)
}

func (s *sizeWriter) Len() int64 {
	return atomic.LoadInt64(&s.bytes)
}
