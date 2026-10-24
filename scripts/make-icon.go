//go:build ignore

// Generates X509 Lens's application icons from the brand artwork.
package main

import (
	"image"
	"image/color"
	"image/png"
	"os"
)

// Windows Store and desktop package icons intentionally use the dark brand
// artwork. The generated files are copied into the MSIX by build_desktop.py.
const source = "brand/logo-dark.png"

func main() {
	logo := load(source)
	os.MkdirAll("build", 0755)
	for path, size := range map[string]int{"build/appicon.png": 1024, "build/store-logo.png": 50, "build/store-square44.png": 44, "build/store-square150.png": 150} {
		writeIcon(logo, path, size)
	}
}

func load(path string) image.Image {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		panic(err)
	}
	return img
}

func writeIcon(src image.Image, path string, size int) {
	bounds := src.Bounds()
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	width, height := float64(bounds.Dx()), float64(bounds.Dy())
	for y := 0; y < size; y++ {
		y0 := bounds.Min.Y + int(float64(y)*height/float64(size))
		y1 := bounds.Min.Y + int(float64(y+1)*height/float64(size))
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < size; x++ {
			x0 := bounds.Min.X + int(float64(x)*width/float64(size))
			x1 := bounds.Min.X + int(float64(x+1)*width/float64(size))
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, b, a, n uint32
			for sy := y0; sy < y1; sy++ {
				for sx := x0; sx < x1; sx++ {
					pr, pg, pb, pa := src.At(sx, sy).RGBA()
					r, g, b, a = r+pr, g+pg, b+pb, a+pa
					n++
				}
			}
			img.SetNRGBA(x, y, color.NRGBA{uint8((r / n) >> 8), uint8((g / n) >> 8), uint8((b / n) >> 8), uint8((a / n) >> 8)})
		}
	}
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err = png.Encode(f, img); err != nil {
		panic(err)
	}
}
