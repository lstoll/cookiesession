package cookiesession

import "testing"

func TestDeriveKeys(t *testing.T) {
	dks, err := KeysFromPassphrases("aaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if len(dks.DecryptionKeys()) != 1 {
		t.Error("decryption key not generated")
	}
}
