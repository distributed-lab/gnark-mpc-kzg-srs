# gnark-mpc-kzg-srs

- [Overview](#overview)
- [Trusted Setup and Powers of Tau](#trusted-setup-and-powers-of-tau)
  - [What is a Trusted Setup?](#what-is-a-trusted-setup)
  - [Powers of Tau](#powers-of-tau)
- [Installation](#installation)
- [Usage](#usage)
  - [Aztec bn254 KZG SRS](#aztec-bn254-kzg-srs)
  - [Aleo bls12-377 KZG SRS](#aleo-bls12-377-kzg-srs)
  - [Celo bw6 KZG SRS](#celo-bw6-kzg-srs)
- [How It Works](#how-it-works)

## Overview
This tool converts a KZG Structured Reference String (SRS) generated by different protocols, for different curves using MPC (Multi Party Computations), to a format compatible with **gnark**. The converted SRS can be used in various cryptographic applications such as **zero-knowledge proofs (ZKPs), polynomial commitments, etc.**.

## Trusted Setup and Powers of Tau

### What is a Trusted Setup?
A **trusted setup** is a cryptographic preprocessing step required in some zero-knowledge proof systems, such as **SNARKs**. The purpose of this setup is to generate structured randomness that allows for efficient proof verification. However, if the secret randomness (often called "toxic waste") is known by an attacker, they could create fraudulent proofs.

### Powers of Tau
The **Powers of Tau** ceremony is a specific type of trusted setup designed to generate a structured reference string (SRS). This involves computing and publishing a sequence of powers of a secret value $\tau$ (tau):

```math
1, \tau, \tau^2, \tau^3, \dots, \tau^n
```

These values are then used to construct polynomial commitments and efficient zero-knowledge proofs.

In the case of KZG commitments, the SRS consists of elliptic curve elements computed from these powers:

```math
\{ g^{\tau^0}, g^{\tau^1}, g^{\tau^2}, \dots, g^{\tau^n} \}
```

where $g$ is a generator of the elliptic curve group. This structured randomness allows efficient cryptographic operations while ensuring security.

## Installation

```sh
# Clone the repository
git clone https://github.com/distributed-lab/gnark_mpc_kzg_srs
cd gnark_mpc_kzg_srs

# Build the executable
go build -o gnark_mpc_kzg_srs
```

## Usage

> [!IMPORTANT]
> To generate the output file the `.WriteDump()` method is used. WriteDump writes the binary encoding of the entire SRS
> memory representation It is meant to be use to achieve fast serialization/deserialization and is not compatible with
> `.WriteTo()`/`.ReadFrom()`. It does not do any validation and doesn't encode points in a canonical form.
>
> In some cases you may want to use the `.WriteTo()` method instead, that require a single line of code change.


### Aztec bn254 KZG SRS

The original Aztec setup ceremony can be found in the [AztecProtocol/ignition-verification](https://github.com/AztecProtocol/ignition-verification) repository. This repository also provides tools to verify that the setup was correctly generated and signed by all participants.

First of all you'll need to download the transcripts from the Aztec setup. You can find them in the 
[AztecProtocol/ignition-verification](https://github.com/AztecProtocol/ignition-verification).

> [!TIP]
> 
> At the time of writing, the transcripts are available by the following link:
>
> ```bash
> curl https://aztec-ignition.s3.eu-west-2.amazonaws.com/MAIN+IGNITION/sealed/transcript<X>.dat -o transcript<X>.dat
> ```
> 
> Here `<X>` is a number from 00, 01 to 19 -- 20 files in total.

Then:

```sh
./gnark_mpc_kzg_srs aztec bn254 <transcripts_directory>
```
- `<transcripts_directory>`: The path to the directory containing **20 transcript files** from the Aztec setup.

> [!IMPORTANT]
> To generate the output file the `.WriteDump()` method is used. WriteDump writes the binary encoding of the entire SRS
> memory representation It is meant to be use to achieve fast serialization/deserialization and is not compatible with
> `.WriteTo()`/`.ReadFrom()`. It does not do any validation and doesn't encode points in a canonical form.
> 
> In some cases you may want to use the `.WriteTo()` method instead, that require a single line of code change.

### Aleo bls12-377 KZG SRS

The original Aleo setup ceremony was generated using [AleoHQ/aleo-setup](https://github.com/AleoHQ/aleo-setup) repository.
The links to download the transcripts can be found in the [ProvableHQ/snarkVM](https://github.com/ProvableHQ/snarkVM) repository.

> [!TIP]
> You may also find [this link](https://setup-staging.aleo.org/transcripts) useful, where all the rounds and participants' signatures are placed.

Especially, the $`\{g^{\tau^i}\}^n_{i=0}`$ for $n = 15$ can be found in the [resources directory](https://github.com/ProvableHQ/snarkVM/blob/82f1dbbf255a3b34d3732f395597a30276227966/parameters/src/mainnet/resources/powers-of-beta-15.usrs), as well as
$g2^{\tau}$ ([here](https://github.com/ProvableHQ/snarkVM/blob/82f1dbbf255a3b34d3732f395597a30276227966/parameters/src/mainnet/resources/beta-h.usrs)). 
The metadata files for setup up to $n == 28$ can be found in the same directory, while the setup files themself can be 
downloaded using [this code](https://github.com/ProvableHQ/snarkVM/blob/82f1dbbf255a3b34d3732f395597a30276227966/parameters/src/mainnet/mod.rs#L23-L43).

<details>
  <summary>If you want to save your time, you can download them using this Rust code</summary>

  ```Rust
  use snarkvm_algorithms::polycommit::kzg10::KZG10;
  use snarkvm_curves::bls12_377::Bls12_377;
  
  const MAX_NUM_POWERS: usize = 1 << 28;
  
  fn main() -> Result<(), Box<dyn std::error::Error>> {
      KZG10::<Bls12_377>::load_srs(MAX_NUM_POWERS).unwrap();
      
      Ok(())
  }
  ```

  ```Toml
  [package]
  name = "setup-downloader"
  version = "0.1.0"
  edition = "2021"
  
  [dependencies]
  snarkvm-algorithms = { version = "1.1.0", git = "https://github.com/AleoHQ/snarkVM.git" }
  snarkvm-curves = { version = "1.1.0", git = "https://github.com/AleoHQ/snarkVM.git" }
  ```

  The files will appear in the ~/.aleo/resources directory.  

</details>

> [!IMPORTANT]
> The file containing $g2^{\tau}$ should be renamed to contain the `g2` substring e.g. `beta-h.usrs` -> `g2-beta-h.usrs`.

Then:

```sh
./gnark_mpc_kzg_srs aleo bls12377 <setup_directory>
```
- `<setup_directory>`: The path to the directory containing aleo setup files.

### Celo BW6-761 KZG SRS

The original Celo BW6-761 trusted setup was generated using the [celo-org/snark-setup](https://github.com/celo-org/snark-setup) repository.
The setup files can be found in the [public gcloud bucket](https://console.cloud.google.com/storage/browser/plumoceremonyphase1).

Files are organized in a specific structure:

- Files are split into 256 chunks (0-255) for manageability
- Each chunk contains contributions from multiple participants
- For each chunk, you should use the file of final contribution (as it contains the final state of the chunk)

File naming typically follows the pattern: `[round].[chunk_number].[contribution_id].[contributor_address]`, where higher contribution IDs represent later contributions.

**Each file contains:**

- A 64-byte BLAKE2b hash at the beginning
- For chunks 0-127: G1 points (tau powers) followed by G2, alpha_G1, and beta_G1 points
- For chunks 128-255: Only G1 points (tau powers) and beta_G2

**Point distribution across chunks:**

- Each chunk typically contains `1,048,576` ($2^{20}$) points
- The last chunk (255) contains `1,048,575` points
- In total, the setup contains `268,435,455` ($2^{28} - 1$) G1 points
- Chunk `0` additionally contains special G2 points needed for verification

> [!IMPORTANT]
> An important detail: The number of G1 points is calculated as $2^{n}  - 1$, where `n` is the power parameter used in the setup.

Usage:

```sh
./gnark_mpc_kzg_srs celo bw6761 <setup_directory>
```
- `<setup_directory>`: The path to the directory containing the Celo BW6-761 setup files.

The tool automatically:

1. Identifies the latest contribution for each chunk
2. Extracts the G1 and G2 points in the correct order
3. Constructs a gnark-compatible KZG SRS


## License
This project is licensed under the MIT License.
