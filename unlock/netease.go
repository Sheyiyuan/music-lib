package unlock

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
)

var (
	ncmCoreKey = []byte("hzHRAmso5kInbaxW")
	ncmMetaKey = []byte("#14ljk_!\\]&0U<'(")
)

func DecryptNCM(encrypted []byte) ([]byte, string, error) {
	if len(encrypted) < 16 || string(encrypted[:8]) != "CTENFDAM" {
		return nil, "", errors.New("invalid ncm file")
	}

	offset := 8
	if offset+2 > len(encrypted) {
		return nil, "", errors.New("invalid ncm header")
	}
	offset += 2

	keyLen, next, ok := readU32LE(encrypted, offset)
	if !ok || next+int(keyLen) > len(encrypted) {
		return nil, "", errors.New("invalid ncm key length")
	}
	keyData := append([]byte(nil), encrypted[next:next+int(keyLen)]...)
	for i := range keyData {
		keyData[i] ^= 0x64
	}
	offset = next + int(keyLen)

	decryptedKey, err := aesECBDecrypt(ncmCoreKey, keyData)
	if err != nil {
		return nil, "", err
	}
	decryptedKey = pkcs7Unpad(decryptedKey)
	if len(decryptedKey) > 17 {
		decryptedKey = decryptedKey[17:]
	}
	if len(decryptedKey) == 0 {
		return nil, "", errors.New("invalid ncm key data")
	}

	keyBox := buildNCMKeyBox(decryptedKey)

	metaLen, next, ok := readU32LE(encrypted, offset)
	if !ok || next+int(metaLen) > len(encrypted) {
		return nil, "", errors.New("invalid ncm meta length")
	}
	metaData := append([]byte(nil), encrypted[next:next+int(metaLen)]...)
	for i := range metaData {
		metaData[i] ^= 0x63
	}
	offset = next + int(metaLen)

	outExt := parseNCMFormat(metaData)

	if offset+9 > len(encrypted) {
		return nil, "", errors.New("invalid ncm payload")
	}
	offset += 9

	imageSize, next, ok := readU32LE(encrypted, offset)
	if !ok {
		return nil, "", errors.New("invalid ncm image length")
	}
	offset = next + int(imageSize)
	if offset > len(encrypted) {
		return nil, "", errors.New("invalid ncm image block")
	}

	audio := append([]byte(nil), encrypted[offset:]...)
	for i := range audio {
		j := byte((i + 1) & 0xff)
		idx := (int(keyBox[j]) + int(keyBox[(int(keyBox[j])+int(j))&0xff])) & 0xff
		audio[i] ^= keyBox[idx]
	}

	if outExt == "" {
		outExt = detectAudioExt(audio)
	}

	return audio, outExt, nil
}

func buildNCMKeyBox(key []byte) [256]byte {
	var box [256]byte
	for i := 0; i < 256; i++ {
		box[i] = byte(i)
	}

	var c, last int
	keyPos := 0
	for i := 0; i < 256; i++ {
		swap := box[i]
		c = (int(swap) + last + int(key[keyPos])) & 0xff
		box[i] = box[c]
		box[c] = swap
		last = c
		keyPos++
		if keyPos >= len(key) {
			keyPos = 0
		}
	}

	return box
}

func parseNCMFormat(metaData []byte) string {
	if len(metaData) <= 22 {
		return ""
	}

	decoded, err := base64.StdEncoding.DecodeString(string(metaData[22:]))
	if err != nil {
		return ""
	}

	decrypted, err := aesECBDecrypt(ncmMetaKey, decoded)
	if err != nil {
		return ""
	}
	decrypted = pkcs7Unpad(decrypted)

	if bytes.HasPrefix(decrypted, []byte("music:")) {
		decrypted = decrypted[len("music:"):]
	}

	var payload struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(decrypted, &payload); err != nil {
		return ""
	}
	return payload.Format
}

func aesECBDecrypt(key, data []byte) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("invalid aes block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Decrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	return out, nil
}

func pkcs7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	pad := int(data[len(data)-1])
	if pad <= 0 || pad > len(data) {
		return data
	}
	for i := 0; i < pad; i++ {
		if data[len(data)-1-i] != byte(pad) {
			return data
		}
	}
	return data[:len(data)-pad]
}

func readU32LE(data []byte, offset int) (uint32, int, bool) {
	if offset+4 > len(data) {
		return 0, offset, false
	}
	return binary.LittleEndian.Uint32(data[offset : offset+4]), offset + 4, true
}

func detectAudioExt(data []byte) string {
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{'f', 'L', 'a', 'C'}) {
		return "flac"
	}
	if len(data) >= 3 && bytes.Equal(data[:3], []byte{'I', 'D', '3'}) {
		return "mp3"
	}
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{'O', 'g', 'g', 'S'}) {
		return "ogg"
	}
	if len(data) >= 8 && bytes.Equal(data[4:8], []byte{'f', 't', 'y', 'p'}) {
		return "m4a"
	}
	return "mp3"
}
