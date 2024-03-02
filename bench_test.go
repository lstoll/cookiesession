package cookiesession

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"encoding/json"
	"io"
	mathrand "math/rand/v2"
	"reflect"
	"sync/atomic"
	"testing"

	sessionpb "github.com/lstoll/cookiesession/internal/proto"
	"google.golang.org/protobuf/proto"
)

func init() {
	gob.Register(map[string]any{})
}

func BenchmarkSerialization(b *testing.B) {
	// this benchmark exists to make sure our desired serialization isn't too slow

	data, protoData := randCookieData(b)

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

	b.Run("protobuf", func(b *testing.B) {
		for range b.N {
			pb, err := proto.Marshal(protoData)
			if err != nil {
				b.Fatal(err)
			}

			b.SetBytes(int64(len(pb)))

			out := new(sessionpb.BenchSession)
			if err := proto.Unmarshal(pb, out); err != nil {
				b.Fatal(err)
			}

			b.StopTimer()
			if !proto.Equal(protoData, out) {
				b.Fatal("data differs")
			}
			b.StartTimer()
		}
	})

	b.Run("gzip protobuf", func(b *testing.B) {
		for range b.N {
			var buf bytes.Buffer

			w := gzip.NewWriter(&buf)
			sw := &sizeWriter{Writer: w}
			pb, err := proto.Marshal(protoData)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := sw.Write(pb); err != nil {
				b.Fatal(err)
			}
			if err := w.Close(); err != nil {
				b.Fatal(err)
			}

			// comparing the raw amout of JSON we process, to equate with the
			// above
			b.SetBytes(sw.Len())

			out := new(sessionpb.BenchSession)

			r, err := gzip.NewReader(&buf)
			if err != nil {
				b.Fatal(err)
			}
			pb, err = io.ReadAll(r)
			if err != nil {
				b.Fatal(err)
			}
			if err := proto.Unmarshal(pb, out); err != nil {
				b.Fatal(err)
			}
			if err := r.Close(); err != nil {
				b.Fatal(err)
			}

			b.StopTimer()
			if !proto.Equal(protoData, out) {
				b.Fatal("data differs")
			}
			b.StartTimer()
		}
	})

}

func BenchmarkCompressionRatio(b *testing.B) {
	// this exists to make sure compression for the data we're taking about
	// makes sense.

	data, protoData := randCookieData(b)

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

		var pbuf bytes.Buffer
		pw := gzip.NewWriter(&pbuf)
		psw := sizeWriter{Writer: pw}
		pb, err := proto.Marshal(protoData)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := psw.Write(pb); err != nil {
			b.Fatal(err)
		}
		if err := pw.Close(); err != nil {
			b.Fatal(err)
		}

		b.ReportMetric(float64(jsw.Len())/float64(gsw.Len()), "json/gob")
		b.ReportMetric(float64(jbuf.Len())/float64(gbuf.Len()), "jsongz/gobgz")
		b.ReportMetric(float64(jbuf.Len())/float64(jsw.Len()), "gz/json")
		b.ReportMetric(float64(gbuf.Len())/float64(gsw.Len()), "gz/gob")

		b.ReportMetric(float64(psw.Len())/float64(jsw.Len()), "proto/jsob")
		b.ReportMetric(float64(pbuf.Len())/float64(jbuf.Len()), "protogz/jsongz")
		b.ReportMetric(float64(jbuf.Len())/float64(jsw.Len()), "gz/json")
		b.ReportMetric(float64(gbuf.Len())/float64(gsw.Len()), "gz/gob")
		b.ReportMetric(float64(pbuf.Len())/float64(psw.Len()), "gz/proto")
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
func randCookieData(b *testing.B) (map[string]any, proto.Message) {
	data := map[string]any{}
	// in the json map, the keys are field names. they're different in proto, so
	// to get an approximation store just the values in a list.
	proto := &sessionpb.BenchSession{}
	for range 10 {
		v := randStr(20)
		data[randStr(10)] = v
		proto.Values = append(proto.Values, v)
		sm := map[string]any{}
		for range 10 {
			v := randStr(20)
			sm[randStr(10)] = v
			proto.Fields = append(proto.Fields, &sessionpb.BenchSession_SubField{Value: v})
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

	return data, proto
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
