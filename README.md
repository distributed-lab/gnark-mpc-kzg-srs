# aztec-to-gnark-srs

- [Overview](#overview)
- [Trusted Setup and Powers of Tau](#trusted-setup-and-powers-of-tau)
  - [What is a Trusted Setup?](#what-is-a-trusted-setup)
  - [Powers of Tau](#powers-of-tau)
- [Installation](#installation)
- [Usage](#usage)

## Overview
This tool converts a KZG Structured Reference String (SRS) generated by Aztec for the **BN254** elliptic curve to a format compatible with **gnark**. The converted SRS can be used in various cryptographic applications such as **zero-knowledge proofs (ZKPs), polynomial commitments, and SNARKs**.

The original Aztec setup ceremony can be found in the [AztecProtocol/ignition-verification](https://github.com/AztecProtocol/ignition-verification) repository. This repository also provides tools to verify that the setup was correctly generated and signed by all participants.

## Trusted Setup and Powers of Tau

### What is a Trusted Setup?
A **trusted setup** is a cryptographic preprocessing step required in some zero-knowledge proof systems, such as **SNARKs**. The purpose of this setup is to generate structured randomness that allows for efficient proof verification. However, if the secret randomness (often called "toxic waste") is known by an attacker, they could create fraudulent proofs.

### Powers of Tau
The **Powers of Tau** ceremony is a specific type of trusted setup designed to generate a structured reference string (SRS). This involves computing and publishing a sequence of powers of a secret value \( \tau \) (tau):

\[
1, \tau, \tau^2, \tau^3, \dots, \tau^n
\]

These values are then used to construct polynomial commitments and efficient zero-knowledge proofs.

In the case of KZG commitments, the SRS consists of elliptic curve elements computed from these powers:

\[
\{ g^{\tau^0}, g^{\tau^1}, g^{\tau^2}, \dots, g^{\tau^n} \}
\]

where \( g \) is a generator of the elliptic curve group. This structured randomness allows efficient cryptographic operations while ensuring security.

## Installation

```sh
# Clone the repository
git clone https://github.com/omegatymbjiep/aztec-to-gnark-srs.git
cd aztec-to-gnark-srs

# Build the executable
go build -o aztec_to_gnark_srs
```

## Usage
```sh
./aztec_to_gnark_srs <transcripts_directory>
```
- `<transcripts_directory>`: The path to the directory containing **20 transcript files** from the Aztec setup.

#### Output
The script will generate an output file named:
```
kzg_srs_bn254_<n>.memdump
```
where `<n>` is the number of G1 points in the SRS. This file can be used as input for **gnark**-compatible applications.

> [!IMPORTANT]
> To generate the output file the `.WriteDump()` method is used. WriteDump writes the binary encoding of the entire SRS
> memory representation It is meant to be use to achieve fast serialization/ deserialization and is not compatible with
> WriteTo / ReadFrom. It does not do any validation and doesn't encode points in a canonical form.
> 
> In some cases you may want to use the `WriteTo` method instead, that require a single line of code change.

#### How It Works
1. Reads **transcript files** containing metadata and elliptic curve points.
2. Extracts **G1 and G2 points** required for the SRS.
3. Constructs a **gnark-compatible** KZG SRS.
4. Writes the SRS to a file.

## License
This project is licensed under the MIT License.