package cookiesession

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// StaticKeys implements the Keys interface, with a set of fixed keys
type StaticKeys struct {
	Encryption [32]byte
	Decryption [][32]byte
}

func (s *StaticKeys) EncryptionKey() [32]byte {
	return s.Encryption
}

func (s *StaticKeys) DecryptionKeys() [][32]byte {
	return s.Decryption
}

// KeysFromPassphrases
func KeysFromPassphrases(encryption string, decryption ...string) (*StaticKeys, error) {
	for _, k := range append([]string{encryption}, decryption...) {
		if len(k) < 20 {
			return nil, fmt.Errorf("passphrase must be at least 20 chars")
		}
	}

	sk := StaticKeys{}

	krdr := hkdf.New(sha256.New, []byte(encryption), nil, nil)
	if _, err := io.ReadFull(krdr, sk.Encryption[:]); err != nil {
		return nil, err
	}

	for _, p := range decryption {
		krdr := hkdf.New(sha256.New, []byte(p), nil, nil)
		var k [32]byte
		if _, err := io.ReadFull(krdr, k[:]); err != nil {
			return nil, err
		}
		sk.Decryption = append(sk.Decryption, k)
	}

	return &sk, nil
}
