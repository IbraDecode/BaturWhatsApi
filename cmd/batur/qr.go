package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
)

func writeQR(path, payload string) error {
	mod := qrMatrix([]byte(payload))
	n := len(mod)
	scale, quiet := 10, 4
	side := (n + 2*quiet) * scale
	img := image.NewGray(image.Rect(0, 0, side, side))
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			my, mx := y/scale-quiet, x/scale-quiet
			if my >= 0 && mx >= 0 && my < n && mx < n && mod[my][mx] {
				img.SetGray(x, y, color.Gray{0})
			} else {
				img.SetGray(x, y, color.Gray{255})
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// qrMatrix is a version-6 QR (41x41), byte mode, ECC L, mask 0.
// 136 data codewords hold one WhatsApp pairing ref.
func qrMatrix(payload []byte) [][]bool {
	const size = 41
	data := qrECC(qrCodewords(payload))
	m := make([][]bool, size)
	fn := make([][]bool, size)
	for i := 0; i < size; i++ {
		m[i] = make([]bool, size)
		fn[i] = make([]bool, size)
	}
	finder := func(oy, ox int) {
		for y := -1; y <= 7; y++ {
			for x := -1; x <= 7; x++ {
				yy, xx := oy+y, ox+x
				if yy < 0 || xx < 0 || yy >= size || xx >= size {
					continue
				}
				fn[yy][xx] = true
				if y < 0 || x < 0 || y > 6 || x > 6 {
					continue
				}
				m[yy][xx] = y == 0 || y == 6 || x == 0 || x == 6 || (y >= 2 && y <= 4 && x >= 2 && x <= 4)
			}
		}
	}
	finder(0, 0)
	finder(0, size-7)
	finder(size-7, 0)
	for i := 8; i < size-8; i++ {
		fn[6][i], fn[i][6] = true, true
		m[6][i], m[i][6] = i%2 == 0, i%2 == 0
	}
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			fn[30+dy][30+dx] = true
			m[30+dy][30+dx] = dy == -2 || dy == 2 || dx == -2 || dx == 2 || (dy == 0 && dx == 0)
		}
	}
	bi := 0
	bits := qrBits(data)
	up := true
	for x := size - 1; x > 0; x -= 2 {
		if x == 6 {
			x--
		}
		for i := 0; i < size; i++ {
			y := i
			if up {
				y = size - 1 - i
			}
			for dx := 0; dx < 2; dx++ {
				xx := x - dx
				if fn[y][xx] {
					continue
				}
				if bi < len(bits) && bits[bi] == 1 {
					m[y][xx] = true
				}
				bi++
			}
		}
		up = !up
	}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if !fn[y][x] && (y+x)%2 == 0 {
				m[y][x] = !m[y][x]
			}
		}
	}
	format := qrBCH(1<<3|0, 0x537, 10) ^ 0x5412
	for i := 0; i < 15; i++ {
		on := format&(1<<(14-i)) != 0
		var y, x int
		switch {
		case i < 6:
			y, x = i, 8
		case i < 8:
			y, x = i+1, 8
		case i == 8:
			y, x = 8, 7
		default:
			y, x = 8, 14-i
			if x >= 6 {
				x++
			}
		}
		m[y][x] = on
		m[8][size-1-i] = on
		if i < 7 {
			m[size-1-i][8] = format&(1<<i) != 0
		}
	}
	m[size-8][8] = true
	return m
}

func qrBits(data []byte) []byte {
	out := make([]byte, 0, len(data)*8)
	for _, b := range data {
		for i := 7; i >= 0; i-- {
			out = append(out, (b>>i)&1)
		}
	}
	return out
}

func qrCodewords(payload []byte) []byte {
	var bits []byte
	add := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, byte((v>>i)&1))
		}
	}
	add(0b0100, 4)
	add(len(payload), 8)
	for _, b := range payload {
		add(int(b), 8)
	}
	add(0, 4)
	for len(bits)%8 != 0 {
		bits = append(bits, 0)
	}
	out := make([]byte, 0, 136)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for j := 0; j < 8 && i+j < len(bits); j++ {
			b = b<<1 | bits[i+j]
		}
		out = append(out, b)
	}
	for len(out) < 136 {
		if len(out)%2 == 0 {
			out = append(out, 0xEC)
		} else {
			out = append(out, 0x11)
		}
	}
	return out[:136]
}

// qrECC appends 18 Reed-Solomon bytes (QR version 6, ECC L, one block).
func qrECC(data []byte) []byte {
	const nsym = 18
	gen := []byte{1}
	for i := 0; i < nsym; i++ {
		next := make([]byte, len(gen)+1)
		for j := range gen {
			next[j+1] ^= gfMul(gen[j], gfExp(i))
		}
		for j := range gen {
			next[j] ^= gen[j]
		}
		gen = next
	}
	msg := make([]byte, len(data)+nsym)
	copy(msg, data)
	for i := 0; i < len(data); i++ {
		coef := msg[i]
		if coef == 0 {
			continue
		}
		for j := 0; j < len(gen); j++ {
			msg[i+j] ^= gfMul(gen[j], coef)
		}
	}
	return append(append([]byte{}, data...), msg[len(data):]...)
}

func gfExp(n int) byte {
	v := byte(1)
	for i := 0; i < n; i++ {
		v = gfMul(v, 2)
	}
	return v
}

func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1d // 0x11d without the x^8 bit, which already shifted out
		}
		b >>= 1
	}
	return p
}

func qrBCH(data, poly, extra int) int {
	v := data << extra
	for i := 14 + extra; i >= extra; i-- {
		if v&(1<<i) != 0 {
			v ^= poly << (i - extra)
		}
	}
	return data<<extra | v
}
