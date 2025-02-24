package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/kzg"

	"linea/aztec-srs-to-gnark/aleo"
	"linea/aztec-srs-to-gnark/aztec"
)

// ConstructSetup is a func to construct Gnark compatible KZG SRS
// from a directory containing setup files.
type ConstructSetup func(setupDir string) (kzg.SRS, int, error)

type ProtocolName string
type CurveName string

const (
	AztecProtocol ProtocolName = "aztec"
	AleoProtocol  ProtocolName = "aleo"
	CeloProtocol  ProtocolName = "celo"

	BN254Curve    CurveName = "bn254"
	BLS12377Curve CurveName = "bls12377"
	BW6761Curve   CurveName = "bw6761"
)

var supportedSetups = map[ProtocolName]map[CurveName]ConstructSetup{
	AztecProtocol: {BN254Curve: aztec.TranslateBn254SRS},
	AleoProtocol:  {BLS12377Curve: aleo.TranslateBls12377SRS},
}

func main() {
	args := os.Args
	if len(args) < 4 || args[1] == "-h" || args[1] == "--help" {
		fmt.Printf("Usage: %s <protocol> <curve> <setup files directory>\n", args[0])
		return
	}

	translateFunc, ok := supportedSetups[ProtocolName(args[1])][CurveName(args[2])]
	if !ok {
		fmt.Println("ERROR: Unsupported protocol or curve, use one of:")

		for protocol := range supportedSetups {
			for curve := range supportedSetups[protocol] {
				fmt.Printf("\t%s %s\n", protocol, curve)
			}
		}

		return
	}

	srs, pointsNum, err := translateFunc(args[3])
	if err != nil {
		fmt.Println(err)
		return
	}

	resultFileName := fmt.Sprintf("kzg_srs_canonical_%d_%s_%s.memdump", pointsNum-1, args[2], args[1])

	f, err := os.Create(resultFileName)
	if err != nil {
		fmt.Printf("Failed to create output SRS file: %v\n", err)
		return
	}

	err = srs.WriteDump(f)
	if err != nil {
		fmt.Printf("Failed to write SRS to file: %v\n", err)
		return
	}

	fmt.Printf("\nSRS successfully created: %s\n", resultFileName)
}
