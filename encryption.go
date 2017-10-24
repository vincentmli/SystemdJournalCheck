package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
	//	"fmt"
)

func AesEncrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func AesDecrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// XOREncryptDecrypt runs a XOR encryption on the input string, encrypting it if it hasn't already been,
// and decrypting it if it has, using the key provided.
func XOREncryptDecrypt(input, key string) (output string) {
	for i := 0; i < len(input); i++ {
		output += string(input[i] ^ key[i%len(key)])
	}

	return output
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func PlainText(encrypted string, key []byte) (decrypted []byte, err error) {

	encrypted_pass := []byte(encrypted)
	decrypted_pass, err := AesDecrypt(key, encrypted_pass)
	check(err)

	return decrypted_pass, err
}

func GetKey(kcfg ClientConfig) (decrypted_key []byte, err error) {
	var buffer bytes.Buffer
	var AesKey2Key string
	var key []byte
	username_reverse := Reverse(kcfg.Notifications.Email.Username)
	encrypted_key, err := strconv.Unquote(`"` + kcfg.Notifications.Email.Key2key + `"`)
	check(err)
	length := len(username_reverse)
	if length < 32 {
		buffer.WriteString(username_reverse)
		for i := 0; i < 32-length; i++ {
			buffer.WriteString("a")
		}
		AesKey2Key = buffer.String()
		AesKey2Key = strings.Replace(AesKey2Key, "i", "2", -1)
		AesKey2Key = strings.Title(AesKey2Key)

	} else {
		AesKey2Key = username_reverse[0:32]
		AesKey2Key = strings.Replace(AesKey2Key, "i", "2", -1)
		AesKey2Key = strings.Title(AesKey2Key)
	}

	key, err = AesDecrypt([]byte(AesKey2Key), []byte(encrypted_key))
	check(err)

	return key, err
}

func Reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
