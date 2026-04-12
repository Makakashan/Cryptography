// Wykonano: Maksym Vatset

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	blockSide     = 8
	blockSize     = blockSide * blockSide // 64 bytes
	bmpHeaderSize = 54
)

type GrayBMP struct {
	Width  int
	Height int // always positive (top-down in memory)
	Pixels []byte
}

func rd16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func rd32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func wr32(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
}

func loadKey(path string) ([blockSize]byte, bool) {
	var key [blockSize]byte

	f, err := os.Open(path)
	if err != nil {
		def := []byte("default-demo-key-for-ecb-cbc-visualization")
		for i := range blockSize {
			key[i] = byte(int(def[i%len(def)]) + i*13)
		}
		return key, false
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil || len(data) == 0 {
		for i := range blockSize {
			key[i] = byte(0xA5 ^ byte(i*7))
		}
		return key, false
	}

	for i := range blockSize {
		key[i] = data[i%len(data)] ^ byte(i*31+17)
	}
	return key, true
}

func pseudoEncryptBlock(in [blockSize]byte, key [blockSize]byte) [blockSize]byte {
	var out [blockSize]byte

	for i := range blockSize {
		a := in[i] ^ key[i]
		b := in[(i+11)&63] ^ key[(i+23)&63]
		c := in[(i+37)&63] ^ key[(i+41)&63]

		r := byte((int(a) + (int(b) << 1) + (int(c) >> 1) + i*17) & 0xFF)
		out[i] = (r << 3) | (r >> 5) // rotl 3
	}

	// light diffusion round
	var tmp [blockSize]byte
	copy(tmp[:], out[:])
	for i := range blockSize {
		out[i] = tmp[i] ^ tmp[(i+1)&63] ^ byte(i*9)
	}

	return out
}

func readBMPToGray(path string) (GrayBMP, error) {
	var bmp GrayBMP

	f, err := os.Open(path)
	if err != nil {
		return bmp, fmt.Errorf("cannot open input BMP: %w", err)
	}
	defer f.Close()

	r := bufio.NewReader(f)

	header := make([]byte, bmpHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return bmp, fmt.Errorf("cannot read BMP header: %w", err)
	}
	if header[0] != 'B' || header[1] != 'M' {
		return bmp, errors.New("not a BMP file")
	}

	dataOffset := int(rd32(header[10:14]))
	width := int(int32(rd32(header[18:22])))
	heightRaw := int(int32(rd32(header[22:26])))
	bpp := int(rd16(header[28:30]))
	compression := int(rd32(header[30:34]))

	if compression != 0 {
		return bmp, errors.New("compressed BMP not supported (must be BI_RGB)")
	}
	if width <= 0 || heightRaw == 0 {
		return bmp, errors.New("unsupported BMP dimensions")
	}
	if bpp != 8 && bpp != 24 {
		return bmp, fmt.Errorf("only 8-bit or 24-bit BMP supported, got %d", bpp)
	}

	absH := heightRaw
	if absH < 0 {
		absH = -absH
	}

	bytesPerPixel := bpp / 8
	rowStrideIn := ((width*bytesPerPixel + 3) / 4) * 4

	// Move to pixel data offset.
	if _, err := f.Seek(int64(dataOffset), io.SeekStart); err != nil {
		return bmp, fmt.Errorf("seek to pixel data failed: %w", err)
	}

	pixels := make([]byte, width*absH)
	row := make([]byte, rowStrideIn)

	for y := range absH {
		if _, err := io.ReadFull(f, row); err != nil {
			return bmp, fmt.Errorf("failed reading BMP rows: %w", err)
		}

		// Convert to top-down in memory.
		dstY := y
		if heightRaw > 0 {
			dstY = absH - 1 - y // source is bottom-up
		}
		dst := pixels[dstY*width : (dstY+1)*width]

		if bpp == 8 {
			copy(dst, row[:width])
		} else {
			for x := range width {
				b := row[x*3+0]
				g := row[x*3+1]
				rr := row[x*3+2]
				gray := (299*int(rr) + 587*int(g) + 114*int(b)) / 1000
				dst[x] = byte(gray)
			}
		}
	}

	bmp.Width = width
	bmp.Height = absH
	bmp.Pixels = pixels
	return bmp, nil
}

func writeGrayBMP8bit(path string, width, height int, pixels []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot open output file: %w", err)
	}
	defer f.Close()

	rowStride := ((width + 3) / 4) * 4
	imageSize := rowStride * height
	paletteSize := 256 * 4
	dataOffset := bmpHeaderSize + paletteSize
	fileSize := dataOffset + imageSize

	hdr := make([]byte, bmpHeaderSize)
	hdr[0], hdr[1] = 'B', 'M'
	wr32(hdr[2:6], uint32(fileSize))
	wr32(hdr[10:14], uint32(dataOffset))
	wr32(hdr[14:18], 40) // DIB header size
	wr32(hdr[18:22], uint32(width))
	wr32(hdr[22:26], uint32(height)) // write bottom-up
	hdr[26], hdr[27] = 1, 0          // planes
	hdr[28], hdr[29] = 8, 0          // 8 bpp
	wr32(hdr[30:34], 0)              // BI_RGB
	wr32(hdr[34:38], uint32(imageSize))
	wr32(hdr[38:42], 2835) // 72 DPI
	wr32(hdr[42:46], 2835)
	wr32(hdr[46:50], 256)
	wr32(hdr[50:54], 0)

	if _, err := f.Write(hdr); err != nil {
		return err
	}

	// Grayscale palette (B,G,R,0)
	for i := range 256 {
		p := []byte{byte(i), byte(i), byte(i), 0}
		if _, err := f.Write(p); err != nil {
			return err
		}
	}

	row := make([]byte, rowStride)
	for y := range height {
		srcY := height - 1 - y // write bottom-up
		copy(row[:width], pixels[srcY*width:(srcY+1)*width])
		for i := range rowStride - width {
			row[width+i] = 0
		}
		if _, err := f.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func encryptECB(bmp GrayBMP, key [blockSize]byte) []byte {
	w, h := bmp.Width, bmp.Height
	out := make([]byte, len(bmp.Pixels))

	var block [blockSize]byte
	for by := 0; by < h; by += blockSide {
		for bx := 0; bx < w; bx += blockSide {
			for dy := range blockSide {
				for dx := range blockSide {
					x := bx + dx
					y := by + dy
					idx := dy*blockSide + dx
					if x < w && y < h {
						block[idx] = bmp.Pixels[y*w+x]
					} else {
						block[idx] = 0
					}
				}
			}

			enc := pseudoEncryptBlock(block, key)

			for dy := range blockSide {
				for dx := range blockSide {
					x := bx + dx
					y := by + dy
					if x < w && y < h {
						out[y*w+x] = enc[dy*blockSide+dx]
					}
				}
			}
		}
	}

	return out
}

func makeIV(key [blockSize]byte) [blockSize]byte {
	var iv [blockSize]byte
	for i := range blockSize {
		iv[i] = key[(i*7)&63] ^ byte(0x5A+i*3)
	}
	return iv
}

func encryptCBC(bmp GrayBMP, key [blockSize]byte) []byte {
	w, h := bmp.Width, bmp.Height
	out := make([]byte, len(bmp.Pixels))

	var block [blockSize]byte
	var mixed [blockSize]byte
	prev := makeIV(key)

	for by := 0; by < h; by += blockSide {
		for bx := 0; bx < w; bx += blockSide {
			for dy := range blockSide {
				for dx := range blockSide {
					x := bx + dx
					y := by + dy
					idx := dy*blockSide + dx
					if x < w && y < h {
						block[idx] = bmp.Pixels[y*w+x]
					} else {
						block[idx] = 0
					}
					mixed[idx] = block[idx] ^ prev[idx]
				}
			}

			enc := pseudoEncryptBlock(mixed, key)
			prev = enc

			for dy := range blockSide {
				for dx := range blockSide {
					x := bx + dx
					y := by + dy
					if x < w && y < h {
						out[y*w+x] = enc[dy*blockSide+dx]
					}
				}
			}
		}
	}

	return out
}

func main() {
	const (
		inFile  = "plain.bmp"
		keyFile = "key.txt"
		outECB  = "ecb_crypto.bmp"
		outCBC  = "cbc_crypto.bmp"
	)

	bmp, err := readBMPToGray(inFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	key, loaded := loadKey(keyFile)

	ecb := encryptECB(bmp, key)
	cbc := encryptCBC(bmp, key)

	if err := writeGrayBMP8bit(outECB, bmp.Width, bmp.Height, ecb); err != nil {
		fmt.Fprintln(os.Stderr, "Error writing", outECB+":", err)
		os.Exit(1)
	}
	if err := writeGrayBMP8bit(outCBC, bmp.Width, bmp.Height, cbc); err != nil {
		fmt.Fprintln(os.Stderr, "Error writing", outCBC+":", err)
		os.Exit(1)
	}

	fmt.Println("Done.")
	fmt.Println("Input:", inFile)
	if loaded {
		fmt.Println("Key:", keyFile, "(loaded)")
	} else {
		fmt.Println("Key:", keyFile, "(default key used)")
	}
	fmt.Println("Output:", outECB+",", outCBC)
}
