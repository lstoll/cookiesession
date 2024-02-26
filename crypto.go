package cookiesession

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"golang.org/x/crypto/hkdf"
)

// encryptData encrypts data using AES in GCM mode with the given key.
func encryptData(key, plaintext []byte, context map[string]string) ([]byte, error) {
	aad, err := encodeMapToAAD(context)
	if err != nil {
		return nil, fmt.Errorf("encoding context: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("reading nonce: %w", err)
	}

	derived, err := deriveKey(key, nonce, aad, len(key)+12)
	if err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}
	dKey, dNonce := derived[:len(key)], derived[len(key):]

	block, err := aes.NewCipher(dKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating gcm: %w", err)
	}

	encrypted := aesGCM.Seal(nil, dNonce, plaintext, aad)

	return append(nonce, encrypted...), nil
}

// decryptData decrypts data encrypted with AES in GCM mode.
func decryptData(key, encrypted []byte, context map[string]string) ([]byte, error) {
	if len(encrypted) < 12 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, encrypted := encrypted[:12], encrypted[12:]

	aad, err := encodeMapToAAD(context)
	if err != nil {
		return nil, fmt.Errorf("encoding context: %w", err)
	}

	derived, err := deriveKey(key, nonce, aad, len(key)+12)
	if err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}
	dKey, dNonce := derived[:len(key)], derived[len(key):]

	block, err := aes.NewCipher(dKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating gcm: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	plaintext, err := aesGCM.Open(nil, dNonce, encrypted, aad)
	if err != nil {
		return nil, fmt.Errorf("opening encrypted data: %w", err)
	}

	return plaintext, nil
}

func deriveKey(secret, salt, info []byte, length int) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, secret, salt, info)
	derivedKey := make([]byte, length)
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return nil, fmt.Errorf("reading from hkdf: %w", err)
	}
	return derivedKey, nil
}

// encodeMapToAAD takes a map[string]string and encodes it into the aws-style
// byte array format, ensuring deterministic output by sorting the keys. If the
// map is empty, nil will be returned.
func encodeMapToAAD(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return nil, nil
	}

	var buffer bytes.Buffer

	// Extract and sort the keys to ensure deterministic output.
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Encode the number of key-value pairs if the map is not empty.
	pairCount := uint16(len(keys))
	if pairCount > 0 {
		if err := binary.Write(&buffer, binary.BigEndian, pairCount); err != nil {
			return nil, fmt.Errorf("failed to write pair count: %w", err)
		}

		for _, key := range keys {
			value := m[key]
			keyBytes := []byte(key)
			valueBytes := []byte(value)

			if err := binary.Write(&buffer, binary.BigEndian, uint16(len(keyBytes))); err != nil {
				return nil, fmt.Errorf("failed to write key length: %w", err)
			}

			if _, err := buffer.Write(keyBytes); err != nil {
				return nil, fmt.Errorf("failed to write key: %w", err)
			}

			if err := binary.Write(&buffer, binary.BigEndian, uint16(len(valueBytes))); err != nil {
				return nil, fmt.Errorf("failed to write value length: %w", err)
			}

			if _, err := buffer.Write(valueBytes); err != nil {
				return nil, fmt.Errorf("failed to write value: %w", err)
			}
		}
	}

	return buffer.Bytes(), nil
}

// decodeAADToMap takes a byte array in the aws-style format and decodes it into a map[string]string.
func decodeAADToMap(data []byte) (map[string]string, error) {
	result := make(map[string]string)

	reader := bytes.NewReader(data)

	var pairCount uint16
	if len(data) > 0 {
		if err := binary.Read(reader, binary.BigEndian, &pairCount); err != nil {
			return nil, fmt.Errorf("failed to read pair count: %w", err)
		}
	}

	for i := 0; i < int(pairCount); i++ {
		var keyLength uint16
		if err := binary.Read(reader, binary.BigEndian, &keyLength); err != nil {
			return nil, fmt.Errorf("failed to read key length: %w", err)
		}

		key := make([]byte, keyLength)
		if _, err := reader.Read(key); err != nil {
			return nil, fmt.Errorf("failed to read key: %w", err)
		}

		var valueLength uint16
		if err := binary.Read(reader, binary.BigEndian, &valueLength); err != nil {
			return nil, fmt.Errorf("failed to read value length: %w", err)
		}

		value := make([]byte, valueLength)
		if _, err := reader.Read(value); err != nil {
			return nil, fmt.Errorf("failed to read value: %w", err)
		}

		result[string(key)] = string(value)
	}

	return result, nil
}
