package aleo

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	blsKzg "github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	"github.com/consensys/gnark-crypto/kzg"
)

func readG1SetupFile(path string, srs *blsKzg.SRS) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open setup file: %w", err)
	}
	defer file.Close()

	var Nbuffer [8]byte
	if _, err = io.ReadFull(file, Nbuffer[:]); err != nil {
		return fmt.Errorf("failed to read number of points: %w", err)
	}
	pointsN := binary.LittleEndian.Uint64(Nbuffer[:])

	if err = readG1Points(file, pointsN, srs); err != nil {
		return fmt.Errorf("failed to read G1 points: %w", err)
	}

	return nil
}

func readG1Points(r io.Reader, n uint64, srs *blsKzg.SRS) error {
	for i := uint64(0); i < n; i++ {
		x, err := extract48ByteFieldElement(r)
		if err != nil {
			return fmt.Errorf("failed to read x-coordinate: %w", err)
		}

		y, err := extract48ByteFieldElement(r)
		if err != nil {
			return fmt.Errorf("failed to read y-coordinate: %w", err)
		}

		point := bls12377.G1Affine{
			X: x,
			Y: y,
		}

		srs.Pk.G1 = append(srs.Pk.G1, point)

		if len(srs.Pk.G1) == 2 {
			fmt.Printf("> a^1*G1: %s %s\n", srs.Pk.G1[1].X.String(), srs.Pk.G1[1].Y.String())
		}
	}

	return nil
}

func readG2SetupFile(path string, srs *blsKzg.SRS) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open setup file: %w", err)
	}
	defer file.Close()

	x1, err := extract48ByteFieldElement(file)
	if err != nil {
		return fmt.Errorf("failed to read x-coordinate c0: %w", err)
	}

	x2, err := extract48ByteFieldElement(file)
	if err != nil {
		return fmt.Errorf("failed to read x-coordinate c1: %w", err)
	}

	y1, err := extract48ByteFieldElement(file)
	if err != nil {
		return fmt.Errorf("failed to read y-coordinate c0: %w", err)
	}

	y2, err := extract48ByteFieldElement(file)
	if err != nil {
		return fmt.Errorf("failed to read y-coordinate c1: %w", err)
	}

	srs.Vk.G2[1] = bls12377.G2Affine{
		X: bls12377.E2{A0: x1, A1: x2},
		Y: bls12377.E2{A0: y1, A1: y2},
	}

	fmt.Printf("> a^1*G2: %s %s\n", srs.Vk.G2[1].X.String(), srs.Vk.G2[1].Y.String())

	return nil
}

// TranslateBls12377SRS reads all the bls12377 setup files and constructs KZG SRS from them.
func TranslateBls12377SRS(setupDir string) (kzg.SRS, int, error) {
	files, err := os.ReadDir(setupDir)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read setup directory '%s': %w", setupDir, err)
	}

	_, _, gen1Aff, gen2Aff := bls12377.Generators()

	srs := new(blsKzg.SRS)

	srs.Pk.G1 = make([]bls12377.G1Affine, 1)
	srs.Pk.G1[0] = gen1Aff
	srs.Vk.G1 = gen1Aff
	srs.Vk.G2[0] = gen2Aff

	// Sort files by name.
	slices.SortFunc(files, func(i os.DirEntry, j os.DirEntry) int {
		return strings.Compare(strings.ToLower(i.Name()), strings.ToLower(j.Name()))
	})

	numProcessed := 0
	for i, file := range files {
		fileName := file.Name()
		filePath := fmt.Sprintf("%s/%s", setupDir, fileName)

		fmt.Printf("Processing file %s\n", fileName)

		if strings.Contains(strings.ToLower(fileName), "g2") {
			err = readG2SetupFile(filePath, srs)
		} else {
			err = readG1SetupFile(filePath, srs)
		}
		if err != nil {
			return nil, 0, fmt.Errorf("failed to read setup file: %w", err)
		}

		fmt.Printf("Processed setup files %d/%d\n", i+1, len(files))
		numProcessed++
	}

	// Precompute the lines when the G2 points are set
	srs.Vk.Lines[0] = bls12377.PrecomputeLines(srs.Vk.G2[0])
	srs.Vk.Lines[1] = bls12377.PrecomputeLines(srs.Vk.G2[1])

	return srs, len(srs.Pk.G1), nil
}

// Extracts a 396-bit integer (48 bytes) stored in little-endian order.
func extract48ByteFieldElement(r io.Reader) (result fp.Element, err error) {
	var buf [48]byte
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return result, fmt.Errorf("failed to read 48 bytes: %w", err)
	}

	result, err = fp.LittleEndian.Element(&buf)
	if err != nil {
		return result, fmt.Errorf("failed to convert bytes to field element: %w", err)
	}

	return result, nil
}
