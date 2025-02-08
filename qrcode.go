package main

import (
	"github.com/skip2/go-qrcode"
)

type TerminalQrCode struct {
	code *qrcode.QRCode
}

func NewTerminalQrCode(data []byte) (*TerminalQrCode, error) {
	qr, err := qrcode.New(string(data), qrcode.Highest)
	if err != nil {
		return nil, err
	}
	return &TerminalQrCode{code: qr}, nil
}

func (t *TerminalQrCode) Print() {
	width := 80 //t.code.Size()
	height := int(float32(width) / 2.0)

	// Create display buffer
	display := make([][]rune, height+1)
	for i := range display {
		display[i] = make([]rune, width+2)
	}

	// Fill display buffer with QR code data
	bitmap := t.code.Bitmap()
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			if y*2 < len(bitmap) && x < len(bitmap[y*2]) {
				if bitmap[y*2][x] {
					display[y+1][x+1] = '█'
				} else {
					display[y+1][x+1] = ' '
				}
			}
		}
	}

	// Print QR code
	for y := 0; y < len(display); y++ {
		for x := 0; x < len(display[y]); x++ {
			if display[y][x] == 0 {
				print(" ")
			} else {
				print(string(display[y][x]))
			}
		}
		println()
	}
}
