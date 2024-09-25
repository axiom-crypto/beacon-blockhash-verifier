# Beacon Blockhash Verifier

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/license/mit)

A smart contract that verifies the integrity of post-Capella historical `blockhash`es via SSZ proofs. These SSZ proofs are made possible by the introduction of SSZ beacon block roots in [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788).

## Contract External API

The contract provides the following functions to verify and access historical blockhash values.

- `isBlockhashVerified(_blockhash)`: Returns `true` if the provided `_blockhash` has been verified before.
- `verifyCurrentBlock()`: Using an SSZ beacon block root (from the EIP 4788 ring buffer) for a given block `x`, validates the `blockhash` of block `x`.
- `verifyRecentHistoricalBlock()`: Using an SSZ beacon block root (from the EIP 4788 ring buffer) for a given block `x`, validates a `blockhash` of block within the range `[x - 8192, x - 1]`.
- `verifyHistoricalBlock()`: Using an SSZ beacon block root (from the EIP 4788 ring buffer) for a given block `x`, validates a `blockhash` of block within the range `[CAPELLA_INIT_BLOCK, x - 8193]`.

## Gas and Calldata Benchmarks

We report execution gas and calldata benchmarks below. Valid proofs will have same calldata sizes below as of the Deneb hardfork. These benchmarks may change as the result of future hardforks.

|                                 | Execution Gas | Calldata Size |
| ------------------------------- | ------------- | ------------- |
| `verifyCurrentBlock()`          | 64011         | 708           |
| `verifyRecentHistoricalBlock()` | 103256        | 1444          |
| `verifyHistoricalBlock()`       | 80896         | 2436          |

## Proving Ethereum blockhashes via SSZ Proofs

We now explain how we prove Ethereum blockhashes into the beacon block root with SSZ proofs. This section assumes an understanding of [SSZ Merkleization](https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md).

### Local and Generalized Indices for SSZ Proofs

As described in the [spec](https://github.com/ethereum/consensus-specs) and [annotated spec](https://eth2book.info/capella/annotated-spec/), verifying inclusion proofs into SSZ Merkleized data structures requires giving a valid Merkle proof into the root and also checking the correct field is chosen by constraining the **generalized index** as described [here](https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md#generalized-merkle-tree-index).

To verify an SSZ proof with respect to a generalized index, we separate it into the following two components:

- **Local Index:** A 0-indexed number indicating location within the structure (either struct or Vector/List), calculated as `generalized_index % prev_power_of_two(generalized_index)`.
  - For a Container (struct), this is its position in the struct.
  - For a Vector or List, it is its index.
- **Tree Height:** Height of the type's SSZ Merkle tree. This should also be the length of any Merkle proof for the type. Calculated as <code>floor(log<sub>2</sub>(generalized_index))</code>.
  - For a Container (struct), can also be calculated as <code>ceil(log<sub>2</sub>(amount_of_fields))</code>.
  - For a Vector, can also be calculated as <code>ceil(log<sub>2</sub>(capacity))</code>.
  - For a List, can also be calculated as <code>ceil(log<sub>2</sub>(max_length)) + 1</code>. The `+ 1` is for the length mix-in.

During verification, the local index's binary representation encodes the left/right path of the Merkle proof, while the tree height constrains the length of the Merkle proof.

### Blockhash Proofs

The beacon block root commits to the entire history of Ethereum blockhashes after the Altair hard fork via its commitment to the beacon state and the following `BeaconState` fields:

- `latest_execution_payload_header` -- contains the most recent Ethereum blockhash.
- `state_roots` -- contains roots of the beacon states and hence Ethereum blockhashes for the past 8192 slots.
- `historical_summaries` -- contains Merkle roots of state and block roots in groups of 8192 back to the Capella hard fork.

This contract uses SSZ proofs for entries of these fields to verify any blockhash after the Capella hard fork into a post-Deneb beacon block root. These proofs take the form of successive Merkle proofs of fields into Merkleized SSZ structs which together form a path from the blockhash in question to the beacon block root. In the rest of this section, we specify the path and the relevant local indices for each of the three cases above.

In all cases, we begin by proving the `state_root` into the beacon block root, which is available in the EVM via [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788). This proof has a local index of 3 and a tree height of 3.

```rust
pub struct BeaconBlock {
      pub slot: Slot,
      pub proposer_index: ValidatorIndex,
      pub parent_root: Root,
****  pub state_root: Root,  ****
      pub body: Root
}
```

The remainder of the SSZ verification follows different flows for each of the three cases, which directly map to the three contract functions.

#### Beacon block root and blockhash are for the same slot (`verifyCurrentBlock()`)

In this case, we need to prove inclusion of the `latest_execution_payload_header.blockhash` field of the `BeaconState` via the fields shown below.

```rust
pub struct BeaconState {
      /** <...> **/
      pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
****  pub latest_execution_payload_header: ExecutionPayloadHeader,  ****
      pub next_withdrawal_index: WithdrawalIndex,
      /** <...> **/
}

pub struct ExecutionPayloadHeader {
      pub parent_hash: Hash32,
      pub fee_recipient: ExecutionAddress,
      pub state_root: Bytes32,
      pub receipts_root: Bytes32,
      pub logs_bloom: ByteVector<BYTES_PER_LOGS_BLOOM>,
      pub prev_randao: Bytes32,
      pub block_number: u64,
      pub gas_limit: u64,
      pub gas_used: u64,
      pub timestamp: u64,
      pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
      pub base_fee_per_gas: U256,
****  pub block_hash: Hash32,  ****
      pub transactions_root: Root,
      pub withdrawals_root: Root,
      pub blob_gas_used: u64,
      pub excess_blob_gas: u64,
}
```

The corresponding local indices and tree heights for a proof of a `blockhash` for slot `n` into the `BeaconBlock` root for slot `n` are:

|                          | Merkleized Data Structure  | Leaf Node          | Root Node          | Local Index | Tree Height |
| ------------------------ | -------------------------- | ------------------ | ------------------ | ----------- | ----------- |
| `BeaconState` Root Proof | `BeaconBlock` for slot `n` | `BeaconState` Root | `BeaconBlock` Root | 3           | 3           |
| Blockhash Proof          | `BeaconState` for slot `n` | `blockhash`        | `BeaconState` Root | 780         | 10          |

#### Beacon block root is within the past 8192 slots of the blockhash (`verifyRecentHistoricalBlock()`)

In this case, the historic state root we are interested in lies in the `state_roots` vector, and its index within the vector is `historic_state_root_slot % 8192`. We must first give a proof from an element of the `state_roots` vector to the current state root:

```rust
/// Current slot instance
pub struct BeaconState {
    /** <...>> **/
      pub block_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
****  pub state_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,  ****
      pub historical_roots: List<Root, HISTORICAL_ROOTS_LIMIT>,
    /** <...> **/
}
```

Finally, we must give a proof from the `latest_execution_payload_header.blockhash` field of the historic state into the historic state root, which uses the following fields:

```rust
/// Historic slot instance
pub struct BeaconState {
    /** <...> **/
      pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
****  pub latest_execution_payload_header:
          ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,  ****
      pub next_withdrawal_index: WithdrawalIndex,
    /** <...> **/
}

/// Historic slot instance
pub struct ExecutionPayloadHeader {
    /** <...> **/
      pub base_fee_per_gas: U256,
****  pub block_hash: Hash32,  ****
      pub transactions_root: Root,
    /** <...> **/
}
```

To summarize to prove the `blockhash` for slot `x` into a `BeaconBlock` root for slot `n` where `n - 8192 <= x < n`, we require the following sequence of proofs with corresponding local indices and tree heights:

|                                     | Merkleized Data Structure  | Leaf Node                     | Root Node                     | Local Index          | Tree Height |
| ----------------------------------- | -------------------------- | ----------------------------- | ----------------------------- | -------------------- | ----------- |
| `BeaconState` Root Proof            | `BeaconBlock` for slot `n` | `BeaconState` Root            | `BeaconBlock` Root            | 3                    | 3           |
| Historical `BeaconState` Root Proof | `BeaconState` for slot `n` | Historical `BeaconState` Root | `BeaconState` Root            | `49152 + (x % 8192)` | 18          |
| Blockhash Proof                     | `BeaconState` for slot `x` | Historical `blockhash`        | Historical `BeaconState` Root | 780                  | 10          |

#### Beacon block root is greater than 8192 slots prior to the blockhash (`verifyHistoricalBlock()`)

In this case, the historic state root we are interested in is committed to in the `historical_summaries` field of the `BeaconState`. Thus, we must give a proof from the `state_summary_root` of the `HistoricalSummary` at index `(historic_state_root_slot - CAPELLA_INIT_SLOT) / 8192` of `historical_summaries` to the current beacon state root.

```rust
/// Current slot instance
pub struct BeaconState {
    /** <...> **/
      pub next_withdrawal_validator_index: ValidatorIndex,
****  pub historical_summaries: List<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>,  ****
}
```

Next, we must prove the historic state root at index `historic_state_root_slot % 8192` of the `state_roots` vector into the `state_summary_root`.

```rust
/// Merkleization slot instance
pub struct BeaconState {
    /** <...> **/
      pub block_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
****  pub state_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,  ****
      pub historical_roots: List<Root, HISTORICAL_ROOTS_LIMIT>,
    /** <...> **/
}
```

Finally, we must prove the `latest_execution_payload_header.blockhash` field of the historic state into the historic state root.

```rust
/// Historic slot instance
pub struct BeaconState {
    /** <...> **/
      pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
****  pub latest_execution_payload_header:
          ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,  ****
      pub next_withdrawal_index: WithdrawalIndex,
    /** <...> **/
}

/// Historic slot instance
pub struct ExecutionPayloadHeader {
    /** <...> **/
      pub base_fee_per_gas: U256,
****  pub block_hash: Hash32,  ****
      pub transactions_root: Root,
    /** <...> **/
}
```

To summarize, to prove the `blockhash` for slot `x` into the `BeaconBlock` root for slot `n` with `CAPELLA_INIT_SLOT <= x < n - 8192`, we must generate the following SSZ proofs with corresponding local indices and tree heights:

|                                     | Merkleized Data Structure                        | Leaf Node                     | Root Node                     | Local Index                                             | Tree Height |
| ----------------------------------- | ------------------------------------------------ | ----------------------------- | ----------------------------- | ------------------------------------------------------- | ----------- |
| `BeaconState` Root Proof            | `BeaconBlock` for slot `n`                       | `BeaconState` Root            | `BeaconBlock` Root            | 3                                                       | 3           |
| `HistoricalSummary` Root Proof      | `BeaconState` for slot `n`                       | `state_summary_root`          | `BeaconState` Root            | `1811939328 + 2 * ((x - CAPELLA_INIT_SLOT) / 8192) + 1` | 31          |
| Historical `BeaconState` Root Proof | `BeaconState` for merkleization slot of slot `n` | Historical `BeaconState` Root | `state_summary_root`          | `x % 8192`                                              | 13          |
| Blockhash Proof                     | `BeaconState` for slot `x`                       | Historical `blockhash`        | Historical `BeaconState` Root | 780                                                     | 10          |

## Using the Proof Generation Backend

To run:

```bash
cp crates/eth_proof_backend/.env.example crates/eth_proof_backend/.env
```

Then, fill out the relevant environment variables. Setting `OPTIMISM_RPC_URL` is optional.

```bash
source crates/eth_proof_backend/.env
cargo run --release
```

By default, the server exposes two endpoints:

### `GET /generate_blockhash_proof`

Generates a set of SSZ proofs to prove a blockhash into a specified beacon block root.

#### Query Parameters

| Parameter          | Required | Description                                                                 |
| ------------------ | -------- | --------------------------------------------------------------------------- |
| `prove_into_block` | Yes      | The block whose SSZ beacon block root the proof should be generated against |
| `prove_from_block` | Yes      | The block whose `blockhash` to verify                                       |

#### Examples

```bash
# CurrentBlock
curl http://localhost:3000/generate_blockhash_proof?prove_from_block=20822991&prove_into_block=20822991
```

<details>
<summary>Click to view full JSON response</summary>
  
<pre><code>
{
    "ssz_proof": {
        "type": "CurrentBlock",
        "blockhash_proof": {
            "branch": [
                "0xdcbf672fc4595064fe10422dcb17202536b2da53dd27b2f2a49bc97efa9bc1ad",
                "0x06ccf7eb988b9e6db8b9df95cd19e4b913e43bfd13292d2c9937ccbabcef4d54",
                "0xac999fc800596f5b57fb7f9df3b68824852ea3768880751413cbf0dc724c53d7",
                "0xd6df8fe94969670a54855026c77387b7fb23e279c098352f62e1bc10d65b33e1",
                "0x536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c",
                "0xebcf9c0300000000000000000000000000000000000000000000000000000000",
                "0x494ba097b2500f1a224013727c11891bef1d485a22300de649ec05ef3bfbb8d3",
                "0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
                "0x29ccd141f1ea891ed7494cb00dd790509edbcbadc851f98c469c3f1c77a998da",
                "0x10bf96a30efcb70cd4697d810f171dbbe777ab63cb75413530a04b4c8a876038"
            ],
            "generalized_index": 1804,
            "leaf": "0x3b60459d7b4f659bd642c1308d95edb028ab5285284fd5dba9f1c78820cfa3b7",
            "local_index": 780,
            "root": "0x712394bfa792683f38e6b167e14806cbc80b7a9c6ad95ffb21e9bf800a734002"
        },
        "curr_state_root_proof": {
            "branch": [
                "0xb1a87aaa635efd3d4c7a40551b1babf5db79e5bb59d396fe607677d8ca8b4882",
                "0x2e9f58cbfdc738f60d5f9c304e3480b923239610fa650ff309259defd96a0d19",
                "0x9364f9f48c2ba1865e7a34a780ff34f6abe74442bb037dd4921d342c95ebd607"
            ],
            "generalized_index": 11,
            "leaf": "0x712394bfa792683f38e6b167e14806cbc80b7a9c6ad95ffb21e9bf800a734002",
            "local_index": 3,
            "root": "0x1eb75a280a75f6f05cafefa43ea93daf78857398c626be53692290f8a71a03a2"
        }
    }
}
</code></pre>
</details>

```bash
# RecentHistoricalBlock
curl http://localhost:3000/generate_blockhash_proof?prove_from_block=20822990&prove_into_block=20822991
```

<details>
<summary>Click to view full JSON response</summary>
  
<pre><code>
  {
    "ssz_proof": {
        "type": "RecentHistoricalBlock",
        "blockhash_proof": {
            "branch": [
                "0x98029a19c321f46cbff4d0b2b445b89458ede54dd95a26cc1c792c1401a4503b",
                "0x52ce89921faea95a8dfe83542bd3199f9b71d7e5679e9437b3f246a466a00377",
                "0xaca01d9075023a3e0b341dec552dbdee7de1793e5635dde9fd82bc4d24416c2b",
                "0xa92b8c3225173e91464cc33e1933f082b9187dc785bb5be3469582d0769d3963",
                "0x536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c",
                "0xdbcf9c0300000000000000000000000000000000000000000000000000000000",
                "0xc603268447c8c1aeb38a961121ca741c51079383dfe007aa081d9bcf281ca304",
                "0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
                "0x3d5656788fc03388c192654b925321cc432287151339c1b3cd0f6b3c199b537d",
                "0x16b63f5157b92c8ef524a615c58f273eea60cdd881f05032dda20181fce95b7c"
            ],
            "generalized_index": 1804,
            "leaf": "0x2b3c66dda429b5b6ab1163f3f22bde73d65c4de83aaa3315e8f06e25b92ddd4d",
            "local_index": 780,
            "root": "0xf0b06a34175f0ed35e352dc74b53724180d00736a028b8c6dce2ed1da3a3f274"
        },
        "curr_state_root_proof": {
            "branch": [
                "0xb1a87aaa635efd3d4c7a40551b1babf5db79e5bb59d396fe607677d8ca8b4882",
                "0x2e9f58cbfdc738f60d5f9c304e3480b923239610fa650ff309259defd96a0d19",
                "0x9364f9f48c2ba1865e7a34a780ff34f6abe74442bb037dd4921d342c95ebd607"
            ],
            "generalized_index": 11,
            "leaf": "0x712394bfa792683f38e6b167e14806cbc80b7a9c6ad95ffb21e9bf800a734002",
            "local_index": 3,
            "root": "0x1eb75a280a75f6f05cafefa43ea93daf78857398c626be53692290f8a71a03a2"
        },
        "hist_state_root_proof": {
            "branch": [
                "0x596f5d6200a0d9250830b702ab8b00df7845c76df0dd43f6ad1a00d9f3b423d5",
                "0x75157b3abce3f02e58172edef173be3ae981d5ddaefec47a65a3185bd9d9f3c2",
                "0x07383ca5dfea8649338facc70f0372de63e603e1756bda99be56fc2208e5146f",
                "0xe54342ab3e010a702674640629b4d1fac8525041ded12d3b250043a2c976b066",
                "0xa4213188f6fe43cc3c24743e98aa344145e8f76c1bd5bd92bfdb0c4c18e6db10",
                "0xa9d167f8822a43cf4bfc53a98615a4ec89938cf3d0563f5ee6ac8b75d217a7e0",
                "0x5171f832f8c26e481e506e8a977d2836471f495175f5fcb18dd2a47fdac54555",
                "0x2c25fcaa72819f1d855dd9ad638c9f150e0354c4b9ce90987e98b5921d0d66bb",
                "0xe18acb7cb9ace0245f98f4aa6c531856ddd54e52b167f10464dd6d71c31ddfff",
                "0x95815ed47c984880cbf646de6dff6c4a3601ea10315c69169dda044514ee9193",
                "0x1cf19aa1bde06cc1ee88c8aa6003839bd4748441dc88b57ffd67c51dc122249e",
                "0xba55c3beba604dc6e2dd73e1df66bfff23449db37f56c786b216ae79ac723fed",
                "0xa0edabcc6649e34ab70018032a8d98b6bb9919bc5ff3719f612c19998c5d7c05",
                "0x4df6b89755125d4f6c5575039a04e22301a5a49ee893c1d27e559e3eeab73da7",
                "0x2c108473d5e0d40b194a4d6a5e2ba4882e503af8b001f2f5be8aa46faa9fe408",
                "0x0a6a24a63d62eb67ee71bed2d625e0520ed44087a8be73a233bbe69861960ed2",
                "0x361b87228d7163a25d6bbb0a02f8ad64928339f60852460b094ece5f98066207",
                "0x4ac58bec03213877dc0995ae186e9d5add2eec166b9efb87a709d410be4fb490"
            ],
            "generalized_index": 316572,
            "leaf": "0xf0b06a34175f0ed35e352dc74b53724180d00736a028b8c6dce2ed1da3a3f274",
            "local_index": 54428,
            "root": "0x712394bfa792683f38e6b167e14806cbc80b7a9c6ad95ffb21e9bf800a734002"
        }
    }
}
</code></pre>
</details>

```bash
# HistoricalBlock
http://localhost:3000/generate_blockhash_proof?prove_from_block=19822990&prove_into_block=20822991
```

<details>
<summary>Click to view full JSON response</summary>
<pre><code>
{
    "ssz_proof": {
        "type": "HistoricalBlock",
        "blockhash_proof": {
            "branch": [
                "0x6fd9b3096bff0d1790bd3d993050839a045e70a9d85d6ef1ebb18d6aabf12d29",
                "0x5c586a0e6af7b31e2014b5414f57c3c85b428051d38cb7b354e2c669ce26edae",
                "0xb0b0e0e758010a3b8b3d53d84ddbbe658ba5bee943d366bbd5ee7dba32ab04a6",
                "0xd1769faa1257912c2f0338e7ef0ae9eb4820a27c0704d1a3e1c2791554043f79",
                "0x9a355fd99247fa5e3eb6f397f1ee992f4f1c694e78b21971a79f1088de1ff37d",
                "0xdbaba80200000000000000000000000000000000000000000000000000000000",
                "0xb0486920ef8aba6826718e8a0a813789c5ae6ad4a84ac2b2c9dbed30e41e0751",
                "0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
                "0xe4c68cda69610de6088c48a749708c1b12c77067dee406a9924237d99c036249",
                "0xfde3524e6a06fdeb50db5e4f2d6adae3c13ec5ea1eea65f81b500f090ab99a74"
            ],
            "generalized_index": 1804,
            "leaf": "0x8fc43310e6d60aafc7a6c7fdcfd1467dfb58db96581270cdbca6e8e7466bb585",
            "local_index": 780,
            "root": "0x728f7db1f406a5d1f98b3d9c2bc62edb9182527abc748d8415180cf6b2491c2d"
        },
        "curr_state_root_proof": {
            "branch": [
                "0xb1a87aaa635efd3d4c7a40551b1babf5db79e5bb59d396fe607677d8ca8b4882",
                "0x2e9f58cbfdc738f60d5f9c304e3480b923239610fa650ff309259defd96a0d19",
                "0x9364f9f48c2ba1865e7a34a780ff34f6abe74442bb037dd4921d342c95ebd607"
            ],
            "generalized_index": 11,
            "leaf": "0x712394bfa792683f38e6b167e14806cbc80b7a9c6ad95ffb21e9bf800a734002",
            "local_index": 3,
            "root": "0x1eb75a280a75f6f05cafefa43ea93daf78857398c626be53692290f8a71a03a2"
        },
        "hist_state_root_proof": {
            "branch": [
                "0xec380a819e9e26740fa118c1e6281b3deac3d47efd45a6996eecbe0d4e8f6d70",
                "0x3f6f4ecc22df9b83f082fc1341faea26a0fa7a8bb3a420d2c629fffa4b27ab4a",
                "0x8d54e8265340b97a6e6183e2bff270b20a60c2d4dffd3d482b2ed1aa9a773d1f",
                "0x001952aede8e188f0c5d9e9d145f3576ff4c2c3b363b239da6bb62da91ccdc4f",
                "0xc58e281926c1e7d6e23381f3e09ac27c49327f86565532fd841ef46d2058e0db",
                "0x61112b64de15e9386e7aee1be8d241ae18417a773bce3facb81b59267d152980",
                "0x0f686be18c68088aaa61f7b1f0d5386c80e3d5dfda37ff98bad194f6a58240af",
                "0xf17c5345ec04e3c10ab012d93360360de9dcfa1abc0038fd05c100b1085732b1",
                "0x23bea9a4b88d9fd162ea680457da45090c2ff825416f16d3c74c653a4a943c3c",
                "0x79c1d461ede6dc15c3dbdfdd77cfe24fba9b969f034486a17104ac426f368bc0",
                "0x3c02e2495f90dc3bb37b7fb81f37c19d95c21c1b53a2f71284e171ac246f01cb",
                "0x41c1acc60eaf7131b6fc313459253abb2beddb96830945a6d3146cc94cddf4fc",
                "0x5c2537f54ae4c5b54af1f7a8564efa78e28cf7c64f0cff5e473f9b67c6b4c3a0"
            ],
            "generalized_index": 15370,
            "leaf": "0x728f7db1f406a5d1f98b3d9c2bc62edb9182527abc748d8415180cf6b2491c2d",
            "local_index": 7178,
            "root": "0x613db5a8b14db003c77131a55c17f8748595e532638ee49d13dd754b2b2e065a"
        },
        "summary_root_proof": {
            "branch": [
                "0xa0b3a50fdc44cb6162ef553e1591f992b59eefadeb9498012b670f4fb591c394",
                "0xf2c1ae8710393719edcdf51d080a5f9c65c73ccf2eecd78ac61eb5735d1cb366",
                "0xf0ca49ac2aab4092fa15fea6d5105e545e5eccd21d5f0ad00335d8ea4dd23b44",
                "0x9eecd9026ae89c0dd2c86927eab644a9d1a70cf366e70c7fc4b7db0f56c2d148",
                "0x29a110731687d206696fedc8d4c2149a6fd7474aeaaf01b33adbc9232f98fa89",
                "0x4798d0e92891c6bff8e0828a487fb7668a6ad8649993fa1e6f9f09d496f6d232",
                "0x0003ded0742f04543164cad80410644f47c79048500aa1cc88996c94098d406a",
                "0xd5fb5effea691d833f3c53c00b390c08aaffa8294e48c7790f4d4ab18c4d9430",
                "0xd24a1778b3e27acf1fd4e5b0eb98626964d6892f8427b9c12f85832c8240c14a",
                "0x460485af574848585860d57ea2bd50835e0b5a2a296e0dcb014483c82debb54f",
                "0x506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1",
                "0xffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b",
                "0x6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220",
                "0xb7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f",
                "0xdf6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e",
                "0xb58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784",
                "0xd49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb",
                "0x8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb",
                "0x8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab",
                "0x95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4",
                "0xf893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f",
                "0xcddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa",
                "0x8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c",
                "0xfeb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167",
                "0xe71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7",
                "0xd201000000000000000000000000000000000000000000000000000000000000",
                "0xf937140000000000000000000000000000000000000000000000000000000000",
                "0xca0823dc4fc61b0baf3fe9a24c98d71b94ef1cfd4987ea92c295254baa20212b",
                "0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
                "0x29ccd141f1ea891ed7494cb00dd790509edbcbadc851f98c469c3f1c77a998da",
                "0x10bf96a30efcb70cd4697d810f171dbbe777ab63cb75413530a04b4c8a876038"
            ],
            "generalized_index": 3959423663,
            "leaf": "0x613db5a8b14db003c77131a55c17f8748595e532638ee49d13dd754b2b2e065a",
            "local_index": 1811940015,
            "root": "0x712394bfa792683f38e6b167e14806cbc80b7a9c6ad95ffb21e9bf800a734002"
        }
    }
}
</code></pre>
</details>

### `GET /generate_eip4788_blockhash_proof`

Generates a set of SSZ proofs to prove a blockhash into a recent beacon block root that is likely to be available in the [EIP-4788 contract](https://etherscan.io/address/0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02).

#### Query Parameters

| Parameter           | Required | Description                                                                                                                                                                                                                                           |
| ------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `eip4788_timestamp` | No       | The EIP-4788 timestamp of the SSZ beacon block root to generate the proof against. If not provided, an SSZ beacon block root near the tip of the chain will be used which ensures that the proof will be verifiable on-chain for as long as possible. |
| `prove_from_block`  | Yes      | The block whose `blockhash` to verify                                                                                                                                                                                                                 |
| `verifier_chain`    | Yes      | The chain on which the proof will be verified. Options: "mainnet", "optimism"                                                                                                                                                                         |

#### Examples

```bash
# CurrentBlock, with set timestamp
http://localhost:3000/generate_eip4788_blockhash_proof?prove_from_block=20829376&verifier_chain=mainnet&eip4788_timestamp=1727288531
```

<details>
<summary>Click to view full JSON response</summary>
  
<pre><code>
{
    "eip4788_timestamp": 1727288531,
    "ssz_proof": {
        "type": "CurrentBlock",
        "blockhash_proof": {
            "branch": [
                "0xc253ac822a789eb41dacdc3b115b3869fd26c1aafec8f78da96aa0684233cae7",
                "0x074eca38742b369f633f96a1cd67f518dab0993c355eeb21ff3e22d79b93e24d",
                "0xe9f3e28f3b42ee5f1ec5152cef5bc55bc1abcb034525a3354f8dd0cbcc330d46",
                "0xd09eb93f051658fcf0fe55087527c73621ca94f75fa652264c9dfd051999638c",
                "0x536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c",
                "0xfb5e9e0300000000000000000000000000000000000000000000000000000000",
                "0x2dbd2627cabfadd446cf9adbff2b01573ffd3289bd6c45b73c0255956a362836",
                "0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
                "0x2ff4bdfcb5e65d88c12b8d64e141759ac58f1d0f851ed720658fd914a01891db",
                "0xf542bff4bd4fa9b5e1ebb6e8a96a6e7d6d69d7769da32d7999ddcc5c72aa974b"
            ],
            "generalized_index": 1804,
            "leaf": "0xb8d4fdea35b4e115e3335e8fc6361062f22fb41ed587703be5137335f423db10",
            "local_index": 780,
            "root": "0x657906374cfd95a9ea194f44ad6c9ac8cbe26c5838304951e4746093c160c40f"
        },
        "curr_state_root_proof": {
            "branch": [
                "0x4c077a041dae0b8d0de8090186f4ea806aef952dd1050d54f031c908b4b174d9",
                "0x67ce6e4299218f7814d4715edcf4702c8fdd957a42ca72979e39f8af7e459020",
                "0x6bf7e8cda1c50f5c971727e6a056c96ffd052f7618f110045d2e148e4d4c9744"
            ],
            "generalized_index": 11,
            "leaf": "0x657906374cfd95a9ea194f44ad6c9ac8cbe26c5838304951e4746093c160c40f",
            "local_index": 3,
            "root": "0x8c1345f0832349abb5a8c0321c699b0b821fe78718743a3709cf3fec4060f700"
        },
    }
}
</code></pre>
</details>

```bash
# RecentHistoricalBlock, with no set timestamp
curl http://localhost:3000/generate_eip4788_blockhash_proof?prove_from_block=20822990&prove_into_block=20822991
```

<details>
<summary>Click to view full JSON response</summary>
  
<pre><code>
{
    "eip4788_timestamp": 1727288531,
    "ssz_proof": {
        "type": "RecentHistoricalBlock",
        "blockhash_proof": {
            "branch": [
                "0xdcbf672fc4595064fe10422dcb17202536b2da53dd27b2f2a49bc97efa9bc1ad",
                "0x06ccf7eb988b9e6db8b9df95cd19e4b913e43bfd13292d2c9937ccbabcef4d54",
                "0xac999fc800596f5b57fb7f9df3b68824852ea3768880751413cbf0dc724c53d7",
                "0xd6df8fe94969670a54855026c77387b7fb23e279c098352f62e1bc10d65b33e1",
                "0x536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c",
                "0xebcf9c0300000000000000000000000000000000000000000000000000000000",
                "0x494ba097b2500f1a224013727c11891bef1d485a22300de649ec05ef3bfbb8d3",
                "0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
                "0x29ccd141f1ea891ed7494cb00dd790509edbcbadc851f98c469c3f1c77a998da",
                "0x10bf96a30efcb70cd4697d810f171dbbe777ab63cb75413530a04b4c8a876038"
            ],
            "generalized_index": 1804,
            "leaf": "0x3b60459d7b4f659bd642c1308d95edb028ab5285284fd5dba9f1c78820cfa3b7",
            "local_index": 780,
            "root": "0x712394bfa792683f38e6b167e14806cbc80b7a9c6ad95ffb21e9bf800a734002"
        },
        "curr_state_root_proof": {
            "branch": [
                "0x4c077a041dae0b8d0de8090186f4ea806aef952dd1050d54f031c908b4b174d9",
                "0x67ce6e4299218f7814d4715edcf4702c8fdd957a42ca72979e39f8af7e459020",
                "0x6bf7e8cda1c50f5c971727e6a056c96ffd052f7618f110045d2e148e4d4c9744"
            ],
            "generalized_index": 11,
            "leaf": "0x657906374cfd95a9ea194f44ad6c9ac8cbe26c5838304951e4746093c160c40f",
            "local_index": 3,
            "root": "0x8c1345f0832349abb5a8c0321c699b0b821fe78718743a3709cf3fec4060f700"
        },
        "hist_state_root_proof": {
            "branch": [
                "0xf0b06a34175f0ed35e352dc74b53724180d00736a028b8c6dce2ed1da3a3f274",
                "0xaba74180bf30c153e39899da14a3787999ee48f8b503650ef80c2d04ecea0b28",
                "0x07383ca5dfea8649338facc70f0372de63e603e1756bda99be56fc2208e5146f",
                "0xe54342ab3e010a702674640629b4d1fac8525041ded12d3b250043a2c976b066",
                "0xa4213188f6fe43cc3c24743e98aa344145e8f76c1bd5bd92bfdb0c4c18e6db10",
                "0xa81cf8fe6fed4768c46016b9480c53e7e40a5e09aaf03c28717015c772c77fbe",
                "0xc9a3d0c632c35efc4b5b72df6486be5bbf360689faf0f02dfbac15c16c90e125",
                "0x2c25fcaa72819f1d855dd9ad638c9f150e0354c4b9ce90987e98b5921d0d66bb",
                "0x749572112712fba58d75f118107527eed37559e2fa178ae6ebd79820ed68472b",
                "0x7fd2903598cde6eedb9e888b743eba9affa5db74a457e64ef63bddaf5b38cadc",
                "0x1cf19aa1bde06cc1ee88c8aa6003839bd4748441dc88b57ffd67c51dc122249e",
                "0xc2988998bee099bb1145e7a53069a5a3efe669bb5683c80899ecae554cbf99fa",
                "0x2bb70fa40139164f1a6170f2d5ef2d5951fef21acbd47859dec636d0aee85484",
                "0x4df6b89755125d4f6c5575039a04e22301a5a49ee893c1d27e559e3eeab73da7",
                "0x7c69b7a7a54b577cf0d81a1bec691bb9ccf6fd6d5a7ae9b68f342946bc737574",
                "0x2bd214f7c45aad91c7e39e26b68a412bfb51b4423583afac3e20bd105f4a9d81",
                "0x6dbfd5a26370267aed7266d749afae5c7786db0f561b75d194fcdc6d4f986d70",
                "0x41e616f226f52a784d3db865449174ddf372408d478abdd31517684d73d4d478"
            ],
            "generalized_index": 316573,
            "leaf": "0x712394bfa792683f38e6b167e14806cbc80b7a9c6ad95ffb21e9bf800a734002",
            "local_index": 54429,
            "root": "0x657906374cfd95a9ea194f44ad6c9ac8cbe26c5838304951e4746093c160c40f"
        }
    }
}
</code></pre>
</details>

## Constructing the Contract Calls

The `GET /generate_eip4788_blockhash_proof` endpoint contains all the data necessary to construct the contract calls for the `verifyCurrentBlock()`, `verifyRecentHistoricalBlock()`, and `verifyHistoricalBlock()` functions. The `.ssz_proof.type` field indicates which function to use.

### `ssz_proof.type: "CurrentBlock"`

| `verifyCurrentBlock()` arg    | Response Field                            |
| ----------------------------- | ----------------------------------------- |
| `timestamp`                   | `.eip4788_timestamp`                      |
| `currentStateRootProof.leaf`  | `.ssz_proof.curr_state_root_proof.leaf`   |
| `currentStateRootProof.proof` | `.ssz_proof.curr_state_root_proof.branch` |
| `blockhashProof.leaf`         | `.ssz_proof.blockhash_proof.leaf`         |
| `blockhashProof.proof`        | `.ssz_proof.blockhash_proof.branch`       |

### `ssz_proof.type: "RecentHistoricalBlock"`

| `verifyRecentHistoricalBlock()` arg | Response Field                                 |
| ----------------------------------- | ---------------------------------------------- |
| `timestamp`                         | `.eip4788_timestamp`                           |
| `currentStateRootProof.leaf`        | `.ssz_proof.curr_state_root_proof.leaf`        |
| `currentStateRootProof.proof`       | `.ssz_proof.curr_state_root_proof.branch`      |
| `historicalStateRootProof.leaf`     | `.ssz_proof.hist_state_root_proof.leaf`        |
| `historicalStateRootProof.proof`    | `.ssz_proof.hist_state_root_proof.branch`      |
| `historicalStateRootLocalIndex`     | `.ssz_proof.hist_state_root_proof.local_index` |
| `blockhashProof.leaf`               | `.ssz_proof.blockhash_proof.leaf`              |
| `blockhashProof.proof`              | `.ssz_proof.blockhash_proof.branch`            |

### `ssz_proof.type: "HistoricalBlock"`

| `verifyHistoricalBlock()` arg    | Response Field                                 |
| -------------------------------- | ---------------------------------------------- |
| `timestamp`                      | `.eip4788_timestamp`                           |
| `currentStateRootProof.leaf`     | `.ssz_proof.curr_state_root_proof.leaf`        |
| `currentStateRootProof.proof`    | `.ssz_proof.curr_state_root_proof.branch`      |
| `summaryRootProof.leaf`          | `.ssz_proof.summary_root_proof.leaf`           |
| `summaryRootProof.proof`         | `.ssz_proof.summary_root_proof.branch`         |
| `stateSummaryRootLocalIndex`     | `.ssz_proof.summary_root_proof.local_index`    |
| `historicalStateRootProof.leaf`  | `.ssz_proof.hist_state_root_proof.leaf`        |
| `historicalStateRootProof.proof` | `.ssz_proof.hist_state_root_proof.branch`      |
| `historicalStateRootLocalIndex`  | `.ssz_proof.hist_state_root_proof.local_index` |
| `blockhashProof.leaf`            | `.ssz_proof.blockhash_proof.leaf`              |
| `blockhashProof.proof`           | `.ssz_proof.blockhash_proof.branch`            |

## Future Maintenance

Future Ethereum hardforks may change the format of the beacon block and beacon state, which may change the generalized indices of different fields committed to in the beacon block root as discussed [here](#constraining-the-generalized-index). There a few possible forms such a change may take:

- The most likely type of change involves appending fields to structs in the beacon state or block. If appending fields causes the number of fields in a struct to exceed a new power of two, the SSZ tree height for Merkleization of that field will increase by 1. This means the generalized indices of the fields in the struct will also need to be updated. As of September 2024, this is expected to happen in the Pectra hard fork.
- Another possible change is a substantial restructuring of beacon state or block fields that affects the structure of SSZ proofs for blockhashes. A historical example of this was the shift of historical `BeaconState` roots from the `historical_roots` List to the `historical_summaries` List in the Capella hardfork. A potential future example is the transition to the `StableContainer` SSZ struct proposed in [EIP-7495](https://eips.ethereum.org/EIPS/eip-7495).

In both cases, the blockhash verifier logic contained in this repo will need to be updated, which we recommend to be done by updating and redeploying the contract. In addition, if the verifier needs to support configurations from multiple incompatible network upgrades, then the verifier will also need to be extended to branch accordingly.
