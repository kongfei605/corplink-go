package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

func ReadLine() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	return reader.ReadString('\n')
}

func B32Decode(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// /*/ deepseek start
// Base32解码（RFC4648带填充）
func b32Decode(s string) []byte {
	data, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err) // 与原Rust的unwrap()保持一致
	}
	return data
}

// WireGuard密钥对生成
func genWgKeypair() (string, string) {
	// 生成32字节随机私钥
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		panic(err)
	}

	// 执行Curve25519私钥Clamping
	clamp(privateKey[:])

	// 生成公钥
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	// Base64编码
	pubB64 := base64.StdEncoding.EncodeToString(publicKey[:])
	privB64 := base64.StdEncoding.EncodeToString(privateKey[:])

	return pubB64, privB64
}

// Curve25519私钥Clamping处理
func clamp(privateKey []byte) {
	privateKey[0] &= 248  // 清除最低3位
	privateKey[31] &= 127 // 清除最高位
	privateKey[31] |= 64  // 设置第六位
}

///*/ deepseek end

func GenWgKeypair() (string, string) {
	var publicKey, privateKey [32]byte

	// Generate private key
	_, err := rand.Read(privateKey[:])
	if err != nil {
		panic(fmt.Sprintf("failed to generate private key: %v", err))
	}

	// Ensure private key follows curve25519 requirements
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Generate public key
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return base64.StdEncoding.EncodeToString(publicKey[:]),
		base64.StdEncoding.EncodeToString(privateKey[:])
}

func GenPublicKeyFromPrivate(privateKeyStr string) (string, error) {
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %v", err)
	}

	var privateKey, publicKey [32]byte
	copy(privateKey[:], privateKeyBytes)

	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return base64.StdEncoding.EncodeToString(publicKey[:]), nil
}

func B64DecodeToHex(s string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(data), nil
}
