# Beacon Blockhash Verifier

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/license/mit)

A smart contract that verifies the integrity of post-Capella historical `blockhash`es via SSZ proofs. These SSZ proofs are made possible by the introduction of SSZ beacon block roots in [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788).

## External API

The contract provides the following functions to verify and access historical blockhash values.

- `isBlockhashVerified(_blockhash)`: Returns `true` if the provided `_blockhash` has been verified before.
- `verifyCurrentBlock()`: Using an SSZ beacon block root (from the EIP 4788 ring buffer) for a given block `x`, validates the `blockhash` of block `x`.
- `verifyRecentHistoricalBlock()`: Using an SSZ beacon block root (from the EIP 4788 ring buffer) for a given block `x`, validates a `blockhash` of block within the range `[x - 8192, x - 1]`.
- `verifyHistoricalBlock()`: Using an SSZ beacon block root (from the EIP 4788 ring buffer) for a given block `x`, validates a `blockhash` of block within the range `[CAPELLA_INIT_BLOCK, x - 8193]`.

## Gas and Calldata Benchmarks

We report execution gas and calldata benchmarks below. Valid proofs will have same calldata sizes below as of the Deneb hardfork. These benchmarks may change as the result of future hardforks.

|                                 | Execution Gas | Calldata Size |
| ------------------------------- | ---- | ---- |
| `verifyCurrentBlock()`          | 64011 | 708  |
| `verifyRecentHistoricalBlock()` | 103256 | 1444 |
| `verifyHistoricalBlock()`       | 80896 | 2436 |

## Proving Ethereum blockhashes via SSZ Proofs

We now explain how we prove Ethereum blockhashes into the beacon block root with SSZ proofs. This section assumes an understanding of [SSZ Merkleization](https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md).

### Local and Generalized Indices for SSZ Proofs

As described in the [spec](https://github.com/ethereum/consensus-specs) and [annotated spec](https://eth2book.info/capella/annotated-spec/), verifying inclusion proofs into SSZ Merkleized data structures requires giving a valid Merkle proof into the root and also checking the correct field is chosen by constraining the **generalized index** as described [here](https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md#generalized-merkle-tree-index).

To verify an SSZ proof with respect to a generalized index, we separate it into the following two components:

- **Local Index:** A 0-indexed number indicating location within the struct, calculated as `generalized_index % prev_power_of_two(generalized_index)`.
  - For a Container (struct), this is its position in the struct.
  - For a Vector or List, it is its index.
- **Tree Height:** Height of the type's SSZ Merkle tree. This should also be the length of any Merkle proof for the type. Calculated as <code>floor(log<sub>2</sub>(generalized_index))</code>.
  - For a Container (struct), can also be calculated as <code>ceil(log<sub>2</sub>(amount_of_fields))</code>.
  - For a Vector, can also be calculated as <code>ceil(log<sub>2</sub>(capacity))</code>.
  - For a List, can also be calculated as <code>ceil(log<sub>2</sub>(max_length)) + 1</code>. The `+ 1` is for the length mix-in.

During verification, the local index's binary representation encodes the left/right path of the Merkle proof, while the tree height constrains the length of the Merkle proof.

### Blockhash Proofs

The beacon block root commits to the entire history of Ethereum blockhashes after the Altair hard fork via its commitment to the beacon state and the following `BeaconState` fields:

* `latest_execution_payload_header` -- contains the most recent Ethereum blockhash.
* `state_roots` -- contains roots of the beacon states and hence Ethereum blockhashes for the past 8192 slots.
* `historical_summaries` -- contains Merkle roots of state and block roots in groups of 8192 back to the Capella hard fork.

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
| ------------------------ | -------------------------- | ------------------ | ------------------ | ------------------------- | ---------------------- |
| `BeaconState` Root Proof | `BeaconBlock` for slot `n` | `BeaconState` Root | `BeaconBlock` Root | 3                 | 3                      |
| Blockhash Proof          | `BeaconState` for slot `n` | `blockhash`        | `BeaconState` Root | 780               | 10                     |

#### Beacon block root is within the past 8192 slots of the blockhash (`verifyRecentHistoricalBlock()`)

In this case, the historic state root we are interested in lies in the `state_roots` vector, and its index within the vector is `historic_state_root_slot % 8192`. We must first give a proof from an element of the  `state_roots` vector to the current state root:

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

|                                     | Merkleized Data Structure  | Leaf Node                     | Root Node                     | Local Index   | Tree Height |
| ----------------------------------- | -------------------------- | ----------------------------- | ----------------------------- | --------------------------- | ---------------------- |
| `BeaconState` Root Proof            | `BeaconBlock` for slot `n` | `BeaconState` Root            | `BeaconBlock` Root            | 3                   | 3                      |
| Historical `BeaconState` Root Proof | `BeaconState` for slot `n` | Historical `BeaconState` Root | `BeaconState` Root            | `LI < 57344`, `LI >= 49152` | 18                     |
| Blockhash Proof                     | `BeaconState` for slot `x` | Historical `blockhash`        | Historical `BeaconState` Root | 780                 | 10                     |

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

|                                     | Merkleized Data Structure                        | Leaf Node                     | Root Node                     | Local Index                            | Tree Height |
| ----------------------------------- | ------------------------------------------------ | ----------------------------- | ----------------------------- | ---------------------------------------------------- | ---------------------- |
| `BeaconState` Root Proof            | `BeaconBlock` for slot `n`                       | `BeaconState` Root            | `BeaconBlock` Root            | 3                                            | 3                      |
| `HistoricalSummary` Root Proof      | `BeaconState` for slot `n`                       | `state_summary_root`          | `BeaconState` Root            | `LI >= 1811939328`, `LI < 1845493760`, `LI % 2 == 1` | 31                     |
| Historical `BeaconState` Root Proof | `BeaconState` for merkleization slot of slot `n` | Historical `BeaconState` Root | `state_summary_root`          | `LI < 8192`, `LI >= 0`                               | 13                     |
| Blockhash Proof                     | `BeaconState` for slot `x`                       | Historical `blockhash`        | Historical `BeaconState` Root | 780                                          | 10                     |



## Future Maintenance

Future Ethereum hardforks may change the format of the beacon block and beacon state, which may change the generalized indices of different fields committed to in the beacon block root as discussed [here](#constraining-the-generalized-index). There a few possible forms such a change may take:

* The most likely type of change involves appending fields to structs in the beacon state or block. If appending fields causes the number of fields in a struct to exceed a new power of two, the SSZ tree height for Merkleization of that field will increase by 1. This means the generalized indices of the fields in the struct will also need to be updated. As of September 2024, this is expected to happen in the Pectra hard fork.
* Another possible change is a substantial restructuring of beacon state or block fields that affects the structure of SSZ proofs for blockhashes. A historical example of this was the shift of historical `BeaconState` roots from the `historical_roots` List to the `historical_summaries` List in the Capella hardfork. A potential future example is the transition to the `StableContainer` SSZ struct proposed in [EIP-7495](https://eips.ethereum.org/EIPS/eip-7495).

In both cases, the blockhash verifier logic contained in this repo will need to be updated, which we recommend to be done by updating and redeploying the contract. In addition, if the verifier needs to support configurations from multiple incompatible network upgrades, then the verifier will also need to be extended to branch accordingly.
