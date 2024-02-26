package cookiesession

import (
	"crypto/aes"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeySizeAES defines the various AES key sizes
type KeySizeAES int

const (
	KeySizeAES128 KeySizeAES = 16
	KeySizeAES192 KeySizeAES = 24
	KeySizeAES256 KeySizeAES = 32
)

// StaticKeys implements the Keys interface, with a set of fixed keys
type StaticKeys struct {
	Encryption []byte
	Decryption [][]byte
}

func (s *StaticKeys) EncryptionKey() []byte {
	return s.Encryption
}

func (s *StaticKeys) DecryptionKeys() [][]byte {
	return s.Decryption
}

// KeysFromPassphrases derives a set of StaticKeys from the given passphrases.
// The passphrases must be at least 20 chars long.
func KeysFromPassphrases(keySize KeySizeAES, encryption string, decryption ...string) (*StaticKeys, error) {
	// this doesn't handle if they change, but is a good setup level validation.
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
		k := make([]byte, keySize)
		if _, err := io.ReadFull(krdr, k[:]); err != nil {
			return nil, err
		}
		sk.Decryption = append(sk.Decryption, k)
	}

	return &sk, nil
}

func validateKeySize(k []byte) error {
	kl := len(k)
	switch kl {
	default:
		return aes.KeySizeError(kl)
	case int(KeySizeAES128), int(KeySizeAES192), int(KeySizeAES256):
		return nil
	}
}
