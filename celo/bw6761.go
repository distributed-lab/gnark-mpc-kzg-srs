package celo

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	bwKzg "github.com/consensys/gnark-crypto/ecc/bw6-761/kzg"
	"github.com/consensys/gnark-crypto/kzg"
)

const (
	// Hash size at the beginning of each file
	HashSize = 64
	// BW6-761 field element size in bytes
	PointCoordinateSize = 96
	// Size of a G1 point (x, y coordinates)
	G1PointSize = bw6761.SizeOfG1AffineUncompressed
	// Size of a G2 point (x, y coordinates) - same size as G1 for BW6-761
	G2PointSize = bw6761.SizeOfG2AffineUncompressed
	// Total number of chunks (256) that divide the full SRS for manageable processing
	// Each chunk typically contains 2^20 points, for a total of ~2^28 points across all chunks
	TotalChunks = 256
	// Halfway point - chunks 128-255 only have G1 points and 1 beta_G2
	// Chunks 0-127 contain G1, G2, alpha_G1, beta_G1, beta_G2
	ChunkHalfwayPoint = 128
	// Regex to extract the chunk number from filenames
	// Expected format: [round].[chunk_number].[contribution_id].[contributor_address]
	ChunkNumberRegexp = `\d+\.(\d+)\..*`
)

var fileRegexp = regexp.MustCompile(ChunkNumberRegexp)

// TranslateBw6761SRS reads the Celo BW6-761 setup files and constructs a KZG SRS
func TranslateBw6761SRS(setupDir string) (kzg.SRS, int, error) {
	files, err := os.ReadDir(setupDir)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read setup directory '%s': %w", setupDir, err)
	}

	_, _, gen1Aff, gen2Aff := bw6761.Generators()

	// Initialize SRS
	srs := new(bwKzg.SRS)
	srs.Pk.G1 = make([]bw6761.G1Affine, 0)
	srs.Vk.G1 = gen1Aff
	srs.Vk.G2[0] = gen2Aff

	// Create a map to store chunks
	chunkFiles := make(map[int]string)

	// Extract chunk numbers from filenames
	for _, file := range files {
		matches := fileRegexp.FindStringSubmatch(file.Name())
		if len(matches) <= 1 {
			continue
		}

		chunkNum, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse chunk number from filename %s: %w", file.Name(), err)
		}

		// If we have multiple files for the same chunk,
		// we'll use the one that appears last alphabetically
		// (which should be the latest contribution)
		if existingFile, ok := chunkFiles[chunkNum]; !ok || strings.Compare(existingFile, file.Name()) < 0 {
			chunkFiles[chunkNum] = file.Name()
		}
	}

	fmt.Printf("Found %d chunk files\n", len(chunkFiles))

	// Process chunks in order
	for chunkNum := 0; chunkNum < TotalChunks; chunkNum++ {
		fileName, ok := chunkFiles[chunkNum]
		if !ok {
			return nil, 0, fmt.Errorf("missing chunk file for chunk %d", chunkNum)
		}

		filePath := filepath.Join(setupDir, fileName)
		fmt.Printf("Processing chunk %d from file %s\n", chunkNum, fileName)

		err := processChunk(filePath, chunkNum, srs)
		if err != nil {
			fmt.Printf("failed to process chunk %d: %v\n", chunkNum, err)
		}

	}

	// Precompute the lines when the G2 points are set
	srs.Vk.Lines[0] = bw6761.PrecomputeLines(srs.Vk.G2[0])
	if !srs.Vk.G2[1].IsInfinity() {
		srs.Vk.Lines[1] = bw6761.PrecomputeLines(srs.Vk.G2[1])
	}

	return srs, len(srs.Pk.G1), nil
}

func processChunk(filePath string, chunkNum int, srs *bwKzg.SRS) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}
	fileSize := fileInfo.Size()

	// Skip the hash at the beginning of the file
	if _, err := file.Seek(int64(HashSize), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek past hash: %w", err)
	}

	// Calculate chunk size
	chunkSize := calculateChunkSize(chunkNum, fileSize)
	buffer := make([]byte, G1PointSize)
	pointsToRead := chunkSize
	pointsProcessed := 0
	pointsAdded := 0

	// Process G1 points
	for i := 0; i < pointsToRead; i++ {
		n, err := io.ReadFull(file, buffer)
		if err != nil {
			if err == io.EOF && i == 0 {
				return fmt.Errorf("unexpected EOF at beginning of file")
			} else if err == io.EOF {
				fmt.Printf("Warning: Reached EOF after reading %d points, expected %d\n", i, pointsToRead)
				break
			} else if err == io.ErrUnexpectedEOF {
				fmt.Printf("Warning: Reached unexpected EOF after reading %d points, expected %d\n", i, pointsToRead)
				break
			}
			return fmt.Errorf("error reading file at point %d: %w", i, err)
		}

		if n < G1PointSize {
			return fmt.Errorf("incomplete read: got %d bytes, expected %d", n, G1PointSize)
		}

		pointsProcessed++

		x, err := extractBw6FieldElement(buffer[:PointCoordinateSize])
		if err != nil {
			return fmt.Errorf("failed to extract x coordinate: %w", err)
		}

		y, err := extractBw6FieldElement(buffer[PointCoordinateSize:])
		if err != nil {
			return fmt.Errorf("failed to extract y coordinate: %w", err)
		}

		point := bw6761.G1Affine{X: x, Y: y}

		if point.IsInfinity() || !point.IsOnCurve() {
			return fmt.Errorf("point at index %d is not on curve or infinity", i)
		}

		srs.Pk.G1 = append(srs.Pk.G1, point)
		pointsAdded++
	}

	// If this is chunk 0, also process the G2 points
	if chunkNum == 0 {
		// File structure for chunk 0:
		// [hash]
		// [tau_g1 points]
		// [tau_g2 points]
		// [alpha_g1 points]
		// [beta_g1 points]
		// [beta_g2 point]

		// At this point, we've already read all the tau_g1 points,
		// so the file pointer should already be positioned at the beginning
		// of the G2 points section.

		// Read the generator (first G2 point)
		g2GeneratorBuffer := make([]byte, G2PointSize)
		if _, err := io.ReadFull(file, g2GeneratorBuffer); err != nil {
			return fmt.Errorf("failed to read G2 generator: %w", err)
		}

		g2GenX, err := extractBw6FieldElement(g2GeneratorBuffer[:PointCoordinateSize])
		if err != nil {
			return fmt.Errorf("failed to parse G2 generator X coordinate: %w", err)
		}

		g2GenY, err := extractBw6FieldElement(g2GeneratorBuffer[PointCoordinateSize:])
		if err != nil {
			return fmt.Errorf("failed to parse G2 generator Y coordinate: %w", err)
		}

		g2Generator := bw6761.G2Affine{X: g2GenX, Y: g2GenY}
		if !g2Generator.IsOnCurve() {
			return fmt.Errorf("G2 generator point is not on curve")
		}

		// Verify this matches the expected G2 generator
		_, _, _, expectedGen2 := bw6761.Generators()
		if !g2Generator.Equal(&expectedGen2) {
			return errors.New("G2 generator in file doesn't match expected generator")
		}

		// Read tau*G2 (second G2 point - tau^1 * G2)
		tauG2Buffer := make([]byte, G2PointSize)
		if _, err := io.ReadFull(file, tauG2Buffer); err != nil {
			return fmt.Errorf("failed to read τG2: %w", err)
		}

		tauG2x, err := extractBw6FieldElement(tauG2Buffer[:PointCoordinateSize])
		if err != nil {
			return fmt.Errorf("failed to parse τG2 X coordinate: %w", err)
		}

		tauG2y, err := extractBw6FieldElement(tauG2Buffer[PointCoordinateSize:])
		if err != nil {
			return fmt.Errorf("failed to parse τG2 Y coordinate: %w", err)
		}

		tauG2 := bw6761.G2Affine{X: tauG2x, Y: tauG2y}
		if !tauG2.IsOnCurve() {
			return fmt.Errorf("tau*G2 point is not on curve")
		}

		// Store the tau*G2 point in the SRS verification key
		srs.Vk.G2[1] = tauG2
		fmt.Printf("Added τG2 from chunk 0\n")
	}

	fmt.Printf("Chunk %d: Processed %d points, added %d valid points\n",
		chunkNum, pointsProcessed, pointsAdded)

	return nil
}

func calculateChunkSize(chunkNum int, fileSize int64) int {
	// All chunks < ChunkHalfwayPoint have tau_g1, tau_g2, alpha_g1, beta_g1
	if chunkNum < ChunkHalfwayPoint {
		// Estimate based on file size - hash
		availableBytes := fileSize - int64(HashSize)
		// tau_g1 takes 1/4
		return int(availableBytes / (4 * int64(G1PointSize)))
	} else {
		// Chunks >= ChunkHalfwayPoint have tau_g1 + beta_g2
		// So subtract 1 beta_g2 point from the total count
		totalPoints := int((fileSize - int64(HashSize)) / int64(G1PointSize))
		return totalPoints - 1 // Subtract beta_g2
	}
}

func extractBw6FieldElement(data []byte) (fp.Element, error) {
	if len(data) != PointCoordinateSize {
		return fp.Element{}, fmt.Errorf("expected %d bytes for BW6-761 field element, got %d", PointCoordinateSize, len(data))
	}

	var buffer [PointCoordinateSize]byte
	copy(buffer[:], data)

	result, err := fp.LittleEndian.Element(&buffer)
	if err != nil {
		return fp.Element{}, fmt.Errorf("failed to convert bytes to field element: %w", err)
	}

	return result, nil
}
