package cookiesession

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
