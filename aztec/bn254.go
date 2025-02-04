package aztec

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bnKzg "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/kzg"
)

// transcriptMetadata Each value is big-endian encoded 4 bytes.
type transcriptMetadata struct {
	// From 0 to 19 - 20 transcripts per participant
	TranscriptN int32
	// Should be always 20
	TotalTranscriptsN int32
	// Should always be 100,000,000
	TotalG1PointsN int32
	// Should always be 1
	TotalG2PointsN int32
	// Number of G1 points in this transcript
	G1PointsN int32
	// Number of G2 points in this transcript (2 for 1st transcript, 0 for the rest)
	G2PointsN int32
	// The index of the 1st G1 point in this transcript
	StartFrom int32
}

func readMetadata(r io.Reader) (transcriptMetadata, error) {
	var metadata transcriptMetadata
	err := binary.Read(r, binary.BigEndian, &metadata)
	return metadata, err
}

// readTranscriptFile The file is structured as follows:
// - A 24-byte header containing metadata
// - 5,040,000 G1 points
// - 2 G2 points (first transcript only)
//   - The first G2 point is z*Gen, where z is the toxic waste from the previous participant
//   - The second G2 point is x*Gen where x is the trusted setup toxic waste
// - A 64-byte BLAKE2B hash of the rest of the file's data
func readTranscriptFile(path string, srs *bnKzg.SRS) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	metadata, err := readMetadata(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	if err = readG1Points(file, int(metadata.G1PointsN), srs); err != nil {
		return fmt.Errorf("failed to read G1 points: %w", err)
	}

	if metadata.G2PointsN != 0 {
		if err = readG2Points(file, srs); err != nil {
			return fmt.Errorf("failed to read G2 points: %w", err)
		}
	}

	// Checksum is skipped here

	return nil
}

// readG1Points G1 are described as a uint64_t[4] array. The first entry is the least
// significant word of the field element. Each 'word' is written in big-endian form.
func readG1Points(r io.Reader, n int, srs *bnKzg.SRS) error {
	for i := 0; i < n; i++ {
		x, err := extract32ByteFieldElement(r)
		if err != nil {
			return fmt.Errorf("failed to read x-coordinate: %w", err)
		}

		y, err := extract32ByteFieldElement(r)
		if err != nil {
			return fmt.Errorf("failed to read y-coordinate: %w", err)
		}

		point := bn254.G1Affine{
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

// readG2Points G2 are described as a uint64_t[4] array. The first entry is the least
// significant word of the field element. Each 'word' is written in big-endian form.
func readG2Points(r io.Reader, srs *bnKzg.SRS) error {
	// Skip the first G2 point that is z*Gen where z is the toxic waste
	// from the previous participant.
	if _, err := io.CopyN(io.Discard, r, 128); err != nil {
		return fmt.Errorf("failed to skip the first G2 point: %w", err)
	}

	x1, err := extract32ByteFieldElement(r)
	if err != nil {
		return fmt.Errorf("failed to read x-coordinate c0: %w", err)
	}

	x2, err := extract32ByteFieldElement(r)
	if err != nil {
		return fmt.Errorf("failed to read x-coordinate c1: %w", err)
	}

	y1, err := extract32ByteFieldElement(r)
	if err != nil {
		return fmt.Errorf("failed to read y-coordinate c0: %w", err)
	}

	y2, err := extract32ByteFieldElement(r)
	if err != nil {
		return fmt.Errorf("failed to read y-coordinate c1: %w", err)
	}

	srs.Vk.G2[1] = bn254.G2Affine{
		X: bn254.E2{A0: x1, A1: x2},
		Y: bn254.E2{A0: y1, A1: y2},
	}

	fmt.Printf("> a^1*G2: %s %s\n", srs.Vk.G2[1].X.String(), srs.Vk.G2[1].Y.String())

	return nil
}

// Extracts a 256-bit integer (32 bytes) stored in little-endian order
func extract32ByteFieldElement(r io.Reader) (result fp.Element, err error) {
	var buf [32]byte
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return result, err
	}

	// Reverse the order of 8-byte chunks
	var reordered [32]byte
	for i := 0; i < 4; i++ {
		copy(reordered[i*8:(i+1)*8], buf[(3-i)*8:(4-i)*8])
	}

	(&result).SetBytes(reordered[:])

	return result, nil
}

// TranslateBn254SRS reads all the bn254 transcripts and constructs KZG SRS from them.
func TranslateBn254SRS(setupDir string) (kzg.SRS, int, error) {
	files, err := os.ReadDir(setupDir)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read setup directory '%s': %w", setupDir, err)
	}

	_, _, gen1Aff, gen2Aff := bn254.Generators()

	srs := new(bnKzg.SRS)

	srs.Pk.G1 = make([]bn254.G1Affine, 1)
	srs.Pk.G1[0] = gen1Aff
	srs.Vk.G1 = gen1Aff
	srs.Vk.G2[0] = gen2Aff

	numProcessed := 0
	for i, file := range files {
		fmt.Printf("Processing file %s\n", file.Name())

		err = readTranscriptFile(fmt.Sprintf("%s/%s", setupDir, file.Name()), srs)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to read setup file: %w", err)
		}

		fmt.Printf("Processed setup files %d/%d\n", i+1, len(files))
		numProcessed++
	}

	if numProcessed != 20 {
		fmt.Printf("WARNING: expected 20 setup files, but got %d\n", numProcessed)
	}

	// Precompute the lines when the G2 points are set
	srs.Vk.Lines[0] = bn254.PrecomputeLines(srs.Vk.G2[0])
	srs.Vk.Lines[1] = bn254.PrecomputeLines(srs.Vk.G2[1])

	return srs, len(srs.Pk.G1), nil
}
