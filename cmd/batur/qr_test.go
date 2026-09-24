package main

import "testing"

func TestQRWrites(t *testing.T) {
	payload := "2@abc,AAAA,BBBB,CCCC,batur"
	if err := writeQR("/tmp/opencode/sample-qr.png", payload); err != nil {
		t.Fatal(err)
	}
}
