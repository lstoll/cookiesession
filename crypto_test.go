package cookiesession

import (
	"bytes"
	"crypto/rand"
	"io"
	"reflect"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	data := "hello world"
	context := map[string]string{"use": "test"}

	k := make([]byte, KeySizeAES128)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		t.Fatal(err)
	}

	enc, err := encryptData(k, []byte(data), context)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := decryptData(k, enc, context)
	if err != nil {
		t.Fatal(err)
	}

	if string(dec) != data {
		t.Errorf("want %s got %s", data, string(dec))
	}
}
func TestAADEncoding(t *testing.T) {
	tm := map[string]string{
		"akey":        "some value",
		"another key": "ljhsdf828",
		"lastkey":     "sasd",
	}

	var last []byte
	for range 10 {
		enc, err := encodeMapToAAD(tm)
		if err != nil {
			t.Fatal(err)
		}
		if last != nil && !bytes.Equal(last, enc) {
			t.Error("encoded format differed")
		}
		last = enc
	}

	dec, err := decodeAADToMap(last)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(tm, dec) {
		t.Errorf("want %v, got: %v", tm, dec)
	}
}
