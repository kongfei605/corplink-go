package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"time"
)

const (
	digits   = 6
	timeStep = 30
)

type TotpSlot struct {
	Code     uint32
	SecsLeft uint32
}

func hotp(key []byte, counter uint64, digitCount uint32) uint32 {
	// Convert counter to byte array
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	// Calculate HMAC-SHA1
	h := hmac.New(sha1.New, key)
	h.Write(counterBytes)
	hmac := h.Sum(nil)

	// Get dynamic binary code
	offset := hmac[len(hmac)-1] & 0xf
	dynRange := hmac[offset : offset+4]

	// Convert to number and truncate
	sNum := binary.BigEndian.Uint32(dynRange) & 0x7fffffff
	return sNum % uint32(pow(10, int(digitCount)))
}

func totpOffset(key []byte, slotOffset int32) TotpSlot {
	now := time.Now().Unix()
	slot := (now / timeStep) + int64(slotOffset)

	code := hotp(key, uint64(slot), digits)
	secsLeft := uint32(timeStep - (now % timeStep))

	return TotpSlot{
		Code:     code,
		SecsLeft: secsLeft,
	}
}

func totp(key []byte) uint32 {
	now := time.Now().Unix()
	slot := now / timeStep
	return hotp(key, uint64(slot), digits)
}

// Helper function to calculate power
func pow(base, exp int) int {
	result := 1
	for i := 0; i < exp; i++ {
		result *= base
	}
	return result
}
