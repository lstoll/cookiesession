package cookiesession

import "context"

// StaticKeys implements the Keys interface, with a set of fixed keys
type StaticKeys struct {
	Encryption [32]byte
	Decryption [][32]byte
}

func (s *StaticKeys) EncryptionKey(context.Context) ([32]byte, error) {
	return s.Encryption, nil
}

func (s *StaticKeys) DecryptionKeys(context.Context) ([][32]byte, error) {
	return s.Decryption, nil
}
