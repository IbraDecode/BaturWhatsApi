package main

import "github.com/skip2/go-qrcode"

func writeQR(path, payload string) error {
	return qrcode.WriteFile(payload, qrcode.Medium, 512, path)
}
