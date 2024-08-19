# GevProver

Gevprover is a customized version of zkEVM-Prover v3.0.2, designed specifically to act as an interface for the Stateless Prover. Unlike the original zkEVM-Prover, all proof generation components have been removed from Gevprover. Its primary function is to connect with the zkEVM node and provide all necessary services and clients. When a proof request is received from the node, Gevprover processes the request, creates an input JSON file, and forwards it to the Gevulot Network. The Gevulot Network then handles the proof generation. Once the proof is generated and returned as a JSON file, Gevprover reconstructs the proof from the JSON data provided by the Gevulot Network.

## Components

### Aggregator client

- It establishes a connection to an Aggregator server.
- Multiple zkEVM Provers can simultaneously connect to the Aggregator server, thereby enhancing the proof generation capability.
- Upon being invoked by the Aggregator service for batch proof generation:
  - The Prover component processes the input data (a set of EVM transactions), computes the resulting state, and creates a proof based on the PIL polynomial definitions and their constraints.
  - The Executor component integrates 14 state machines to process the input data and produce evaluations of the committed polynomials, essential for proof generation. Each state machine generates its computational evidence, and intricate calculations are passed on to the subsequent state machine.
- The Prover component then invokes the Stark component to produce a proof for the committed polynomials from the Executor's state machines.
- When tasked by the Aggregator service to produce an aggregated proof:
  - The Prover component amalgamates the results of two previously computed batch or aggregated proofs, supplied by the Aggregator, to create an aggregated proof.
- When tasked by the Aggregator service to produce a final proof:
  - The Prover component uses the outcome of a prior aggregated proof, supplied by the Aggregator, to formulate a conclusive proof that can be validated.
- The server interface for this service is delineated in the file named `aggregator.proto`.

### Executor service

- The Executor component processes the input data, which comprises a batch of EVM transactions, and computes the resulting state. Notably, no proof is produced.
- This service offers a swift method to verify whether a proposed batch of transactions is correctly constructed and if it aligns with the workload that can be proven in a single batch.
- When the Executor service invokes the Executor component, only the Main state machine is utilized. This is because the committed polynomials aren't needed, given that a proof isn't generated.
- The service's interface is outlined in the `executor.proto` file.

### StateDB service

- This service provides an interface to access the system's state (represented as a Merkle tree) and the database where this state is stored.
- Both the executor and the prover rely on it as the unified source of state. It can be utilized to retrieve specific state details, such as account balances.
- The interface for this service is described in the `statedb.proto` file.
- Recent changes have been made to the `HashDB` service.
- The `HashDB` service now exports old state roots from the `StateDB` service.
- These old state roots are included in the input JSON specifically for `BATCH_PROOF` requests.
- Since generating a `BATCH_PROOF` requires old state roots, they are sent within the input JSON to the Stateless Prover.

### Prover

- The `Prover` component handles proof requests from the node.
- Functions `genBatchProof`, `genAggregatedProof`, and `genFinalProof` are responsible for processing these requests.
- All proof generation logic has been removed from these functions.
- When a request is received:
  - The JSON is extracted from the `ProverRequest`.
  - The JSON data is then sent to the `Gevson` component for further processing.

### Gevson

- The `Gevson` component is designed to communicate with the Gevulot Network.
- Utilizes `gevulot-cli` for interacting with the Gevulot Network.
- The primary function is `generateProof`, which handles proof generation.
- `generateProof` takes two parameters:
  - `vector<json> files`: A vector containing JSON input files.
  - `proof_type`: The type of proof, which can be `BATCH_PROOF`, `AGGREGATED_PROOF`, or `FINAL_PROOF`.
- Process flow of `generateProof`:
  - Deploys all JSON input files in the `files` vector to AWS S3 using `s3cmd`.
  - Calculates hashes for the files using `gevulot-cli`.
  - Creates a transaction from the input and sends it to the Gevulot Network.
  - Awaits proof generation from the Gevulot Network.
  - While waiting, `Gevson` can accept additional requests.
  - Once proof generation is complete, `Gevson` receives the response.
  - The response is sent back to the respective functions (`genBatchProof`, `genAggregatedProof`, or `genFinalProof`).
  - Finally, the response is returned to the node.

## Compiling locally

Steps to compile `zkevm-prover` locally:
### Clone repository

```sh
git clone --recursive https://github.com/SnarkLabs/gevprover.git
cd zkevm-prover
```
### Install dependencies

The following packages must be installed.

**Important dependency note**: you must install [`libpqxx` version 6.4.5](https://github.com/jtv/libpqxx/releases/tag/6.4.5). If your distribution installs a newer version, please [compile `libpqxx` 6.4.5](https://github.com/jtv/libpqxx/releases/tag/6.4.5) and install it manually instead.

#### Ubuntu/Debian

```sh
sudo apt update
sudo apt install build-essential libbenchmark-dev libomp-dev libgmp-dev nlohmann-json3-dev postgresql libpqxx-dev libpqxx-doc nasm libsecp256k1-dev libcurl4-openssl-dev libsodium-dev libprotobuf-dev libssl-dev cmake libgrpc++-dev protobuf-compiler protobuf-compiler-grpc uuid-dev s3cmd
```

#### openSUSE
```sh
zypper addrepo https://download.opensuse.org/repositories/network:cryptocurrencies/openSUSE_Tumbleweed/network:cryptocurrencies.repo
zypper refresh
zypper install -t pattern devel_basis
zypper install libbenchmark1 libomp16-devel libgmp10 nlohmann_json-devel postgresql libpqxx-devel ghc-postgresql-libpq-devel nasm libsecp256k1-devel grpc-devel libsodium-devel libprotobuf-c-devel libssl53 cmake libgrpc++1_57 protobuf-devel uuid-devel llvm llvm-devel libopenssl-devel s3cmd
```

#### Fedora
```
dnf group install "C Development Tools and Libraries" "Development Tools"
dnf config-manager --add-repo https://terra.fyralabs.com/terra.repo
dnf install google-benchmark-devel libomp-devel gmp gmp-devel gmp-c++ nlohmann-json-devel postgresql libpqxx-devel nasm libsecp256k1-devel grpc-devel libsodium-devel cmake grpc grpc-devel grpc-cpp protobuf-devel protobuf-c-devel uuid-devel libuuid-devel uuid-c++ llvm llvm-devel openssl-devel s3cmd
```

#### Arch
```sh
pacman -S base-devel extra/protobuf community/grpc-cli community/nlohmann-json extra/libpqxx nasm extra/libsodium community/libsecp256k1
```

### Install `gevulot-cli`

Run the following command to install `gevulot-cli`:
```bash
cargo install --git https://github.com/gevulotnetwork/gevulot.git gevulot-cli
```
___Note:__ Make sure rust is installed. Please refer to gevulot's doc for [key registration](https://docs.gevulot.com/gevulot-docs/devnet/key-registration)._

### Configure `s3cmd`:
Run the following command and fill in all the information in the interactive shell to configure `s3cmd`:
```bash
s3cmd --configure
```

Run the following command to test `s3cmd` configuration:
```bash
echo "This is a test" > test.txt
s3cmd put ./test.txt s3://<CONFIGURED_BUCKET_NAME>/test.txt
```

### Compilation

You may first need to recompile the protobufs:
```sh
cd src/grpc
make
cd ../..
```

Run `make` to compile the main project:

```sh
make clean
make -j
```

To compile in debug mode, run `make -j dbg=1`.

### Test vectors

```sh
./build/zkProver -c config/config.batch_proof.json
```

## StateDB service database

To use persistence in the StateDB (Merkle-tree) service you must create the database objects needed by the service. To do this run the shell script:

```sh
./tools/statedb/create_db.sh <database> <user> <password>
```

For example:

```sh
./tools/statedb/create_db.sh testdb statedb statedb
```

## Docker

```sh
sudo docker build -t zkprover .
docker run -e AWS_ACCESS_KEY_ID=<ACCESS_KEY> -e AWS_SECRET_ACCESS_KEY=<SECRET_ACCESS_KEY> -e AWS_DEFAULT_REGION=<YOUR_REGION> --network host gevprover zkProver
```

## Usage

To run the Prover, supply a `config.json` file containing the parameters that help customize various Prover settings. By default, the Prover accesses the `config.json` file from the `testvectors` directory. Below are some of the key parameters, accompanied by their default values from the given `config.json`:

| Parameter              | Description |
| ---------------------- | ----------- |
| `runStateDBServer`     | Enables StateDB GRPC service, provides SMT (Sparse Merkle Tree) and Database access |
| `gevulotURL`     | Provide the gevulot RPC URL here so `gevson` can send txs to gevulot network |
| `gevsonKeyfilePath`     | Required by `gevson` to send txs to gevulot network |
| `awsBucketName`     | Required by `gevson` for uploading files to specific bucket on AWS |
| `awsRegion`     | It is also required by `gevson` for uploading files on AWS |
| `gevulotProverHash`     | (Optional) It is the prover hash of deployed prover on gevulot network, It's set by default |
| `gevulotVerifierHash`     | (Optional) It is the verifier hash of deployed verifier on gevulot network, It's set by default |
| `runExecutorServer`    | Enables Executor GRPC service, provides a service to process transaction batches    |
| `runAggregatorClient`  | Enables Aggregator GRPC client, connects to the Aggregator and process its requests |
| `aggregatorClientHost` | IP address of the Aggregator server to which the Aggregator client must connect to  |
| `runProverServer`      | Enables Prover GRPC service                                                         |
| `runFileProcessBatch`  | Processes a batch using as input a JSON file defined in the `"inputFile"` parameter |
| `runFileGenProof`      | Generates a proof using as input a JSON file defined in the `"inputFile"` parameter |
| `inputFile`            | Input JSON file with path relative to the `testvectors` folder                      |
| `outputPath`           | Output path to store the result files, relative to the `testvectors` folder         |
| `saveRequestToFile`    | Saves service received requests to a text file                                      |
| `saveResponseToFile`   | Saves service returned responses to a text file                                     |
| `saveInputToFile`      | Saves service received input data to a JSON file                                    |
| `saveOutputToFile`     | Saves service returned output data to a JSON file                                   |
| `databaseURL`          | For the StateDB service, if the value is `"local"`, data is stored in memory; otherwise, use the PostgreSQL format: `"postgresql://<user>:<password>@<ip>:<port>/<database>"`, e.g., `"postgresql://statedb:statedb@127.0.0.1:5432/testdb"`. |
| `stateDBURL`           | For the StateDB service, if the value is "`local"`, a local client replaces the GRPC service. Use the format: `"<ip>:<port>", e.g., "127.0.0.1:50061"`. |

To execute a proof test:

1. Modify the `config.json` file, setting the `"runFileGenProof"` parameter to `"true"`. Ensure all other parameters are set to `"false"`. If you prefer not to use a PostgreSQL database for the test, adjust the `"databaseURL"` to `"local"`.
2. For the `"inputFile"` parameter, specify the desired input test data file. As an example, the `testvectors` directory contains the `input_executor.json` file.
3. Launch the Prover from the `testvectors` directory using the command: `../build/zkProver`.
4. The proof's result files will be saved in the directory defined by the `"outputPath"` configuration parameter.
