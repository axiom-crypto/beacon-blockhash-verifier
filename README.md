# Beacon Blockhash Verifier

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/license/mit)

A smart contract that verifies the integrity of post-Capella historical `blockhash`es via SSZ proofs. These SSZ proofs are made possible by the introduction of SSZ beacon block roots in [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788).

## External API

- `isBlockhashVerified(_blockhash)`: Returns `true` if the provided `_blockhash` has been verified before.
- `verifyCurrentBlock()`: Using an SSZ beacon block root (from the EIP 4788 ring buffer) for a given block `x`, validates the `blockhash` of block `x`.
- `verifyRecentHistoricalBlock()`: Using an SSZ beacon block root (from the EIP 4788 ring buffer) for a given block `x`, validates a `blockhash` of block within the range [x - 8192, x - 1].
- `verifyHistoricalBlock()`: Using an SSZ beacon block root (from the EIP 4788 ring buffer) for a given block `x`, validates a `blockhash` of block within the range [x - 8193, CAPELLA_INIT_BLOCK].

## Gas and Calldata Benchmarks

We report execution gas and calldata benchmarks below. Valid proofs will have same calldata sizes below as of the Deneb hardfork. These benchmarks may change as the result of future hardforks.

|                                 | Execution Gas | Calldata Size |
| ------------------------------- | ---- | ---- |
| `verifyCurrentBlock()`          | 64011 | 708  |
| `verifyRecentHistoricalBlock()` | 103256 | 1444 |
| `verifyHistoricalBlock()`       | 80896 | 2436 |

## SSZ Proofs

> [!NOTE]
> The following sections assume an understanding of SSZ [Merkleization](https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md).

### Constraining the Generalized Index

When verifying SSZ proofs, it is not enough to only verify the Merkle proof; the generalized index must be tightly constrained as well. Otherwise, the verification only asserts that _the piece of data exists somewhere in the beacon block structure_, not that _the piece of data lies within some field or list-like entity within the beacon block structure_.

![image](https://github.com/user-attachments/assets/c81afdc4-d2cd-468f-bc34-f258dda906e1)

In the example above, if we want to prove the value at `b`, we must constrain the generalized index to be 3; otherwise, if the value at `a` had the same value, it could also be validly proven into the root.

However, these generalized indices are subject to change if the underlying data structure is altered. Consider this change:

![image](https://github.com/user-attachments/assets/2030f574-f6d1-4489-9778-3e2f0d6923c9)

Now, the generalized index of `b` is 5.

In order to verify an SSZ proof with respect to a generalized index, we must first realize that GI can be separated into two components:

- **Local Index:** A 0-indexed number indicating location within the structure. These are marked as blue in the images above. Calculated as `generalized_index % prev_power_of_two(generalized_index)`.
  - For a Container (struct), this is its position in the struct.
  - For a Vector or List, it is its index.
- **Tree Height:** Height of the type's SSZ Merkle tree. This should also be the length of any Merkle proof for the type. Calculated as <code>floor(log<sub>2</sub>(generalized_index))</code>.
  - For a Container (struct), can also be calculated as <code>ceil(log<sub>2</sub>(amount_of_fields))</code>.
  - For a Vector, can also be calculated as <code>ceil(log<sub>2</sub>(capacity))</code>.
  - For a List, can also be calculated as <code>ceil(log<sub>2</sub>(max_length)) + 1</code>. The `+ 1` is for the length mix-in.

During verification, the local index's binary form encodes the left/right path of the Merkle proof. The tree height will constrain the length of the Merkle proof.

> [!NOTE]
> It is assumed that the most likely changes across hardfork are appends to structs. In this case, only tree heights may need to reconfigured before redeploying.

### Blockhash Proofs

An SSZ beacon block root commits to the entire history of Ethereum blockhashes post-Altair-hardfork. Thus, a **blockhash proof** is defined as proving the validity of a historical blockhash into an SSZ beacon block further into the future.

_The contract in this repo only supports proving post-Merge (Capella and beyond) blockhashes._

To prove the validity of a blockhash, we prove the validity of nested segments individually which, when combined, build a path from the blockhash to the beacon block root.

Beginning at the top, the first segment is made from the merkleization of the beacon block (beacon block root) to its state_root field. The beacon block root is available in the EVM.

```rust
pub struct BeaconBlock {
      pub slot: Slot,
      pub proposer_index: ValidatorIndex,
      pub parent_root: Root,
////  pub state_root: Root,  ////
      pub body: Root
}
```

Once at the state root, the rest of the segments break down into three separate cases (directly mapping to the three entrypoints of the contract).

#### SSZ beacon block root and blockhash being proven are for the same slot (`verifyCurrentBlock()`)

This is by far the simplest proof. We will simply want another segment to the `latest_execution_payload_header.blockhash` field of the state.

```rust
pub struct BeaconState {
      /** snip **/

      pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
////  pub latest_execution_payload_header: ExecutionPayloadHeader,  ////
      pub next_withdrawal_index: WithdrawalIndex,

      /** snip **/
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
////  pub block_hash: Hash32,  ////
      pub transactions_root: Root,
      pub withdrawals_root: Root,
      pub blob_gas_used: u64,
      pub excess_blob_gas: u64,
}
```

##### Generalized Index Constraints

Given `BeaconBlock` Root for slot `n` and some `blockhash` to prove for slot `x` where `x == n`.

|                          | Merkleized Data Structure  | Leaf Node          | Root Node          | Local Index Constraint(s) | Tree Height Constraint |
| ------------------------ | -------------------------- | ------------------ | ------------------ | ------------------------- | ---------------------- |
| `BeaconState` Root Proof | `BeaconBlock` for slot `n` | `BeaconState` Root | `BeaconBlock` Root | `LI == 3`                 | 3                      |
| Blockhash Proof          | `BeaconState` for slot `n` | `blockhash`        | `BeaconState` Root | `LI == 780`               | 10                     |

#### SSZ beacon block root is within the past 8192 slots of the blockhash being proven (`verifyRecentHistoricalBlock()`)

In this case, the historic state root we are interested in lies in the `state_roots` vector. Its index within the vector can be calculated with `historic_state_root_slot % 8192`. The proof from an index within the `state_roots` vector to the current state root will form a second segment.

```rust
/// Current slot instance
pub struct BeaconState {
    /** snip **/

      pub block_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
****  pub state_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,  ****
      pub historical_roots: List<Root, HISTORICAL_ROOTS_LIMIT>,

    /** snip **/
}
```

Finally, we will require the full state of the historic slot we are interested in. Then, the final segment will be a proof from the `latest_execution_payload_header.blockhash` field of the historic state into the historic state root.

```rust
/// Historic slot instance
pub struct BeaconState {
    /** snip **/

      pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
////  pub latest_execution_payload_header:
          ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,  ////
      pub next_withdrawal_index: WithdrawalIndex,

    /** snip **/
}

/// Historic slot instance
pub struct ExecutionPayloadHeader {
    /** snip **/

      pub base_fee_per_gas: U256,
////  pub block_hash: Hash32,  ////
      pub transactions_root: Root,

    /** snip **/
}
```

For the full proof to be valid, all segments must be valid merkle proofs. Additionally, the root of segment 3 must be the leaf of segment 2 and the root of segment 2 must be the leaf of segment 1.

##### Generalized Index Constraints

Given `BeaconBlock` Root for slot `n` and some `blockhash` to prove for slot `x` where `n - 8192 <= x < n`.

|                                     | Merkleized Data Structure  | Leaf Node                     | Root Node                     | Local Index Constraint(s)   | Tree Height Constraint |
| ----------------------------------- | -------------------------- | ----------------------------- | ----------------------------- | --------------------------- | ---------------------- |
| `BeaconState` Root Proof            | `BeaconBlock` for slot `n` | `BeaconState` Root            | `BeaconBlock` Root            | `LI == 3`                   | 3                      |
| Historical `BeaconState` Root Proof | `BeaconState` for slot `n` | Historical `BeaconState` Root | `BeaconState` Root            | `LI < 57344`, `LI >= 49152` | 18                     |
| Blockhash Proof                     | `BeaconState` for slot `x` | Historical `blockhash`        | Historical `BeaconState` Root | `LI == 780`                 | 10                     |

#### SSZ beacon block root is NOT within the past 8192 slots of the blockhash being proven

In this case, the historic state root we are interested in is committed to in the `historical_summaries` field of the `BeaconState`. The second segment here will be a proof from the appropriate index of `historical_summaries` to the current state root. The `historical_summaries_index` can be calculated with `(historic_state_root_slot - CAPELLA_INIT_SLOT) / 8192`.

```rust
/// Current slot instance
pub struct BeaconState {
      ... snip ...

      pub next_withdrawal_validator_index: ValidatorIndex,
****  pub historical_summaries: List<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>,  ****
}
```

The third segment will depend on the full state of the slot in which the historic root was merkleized. Merkleization takes place every 8192 slots and `merkleization_slot` can be calculated with `(historical_summaries_index + 1) * 8192 + CAPELLA_INIT_SLOT`. On this piece of state, our historic root will be found in the `state_roots` vector at index `historic_state_root_slot % 8192`. So the third segment will be a proof from the appropriate index of the vector (our historic state root) to the historic summary root.

```rust
/// Merkleization slot instance
pub struct BeaconState {
    ... snip ...

      pub block_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
****  pub state_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,  ****
      pub historical_roots: List<Root, HISTORICAL_ROOTS_LIMIT>,

    ... snip ...
}
```

The fourth and final segment will require the full state of the historic slot. It will be a proof from the `latest_execution_payload_header.blockhash` field of the historic state to the historic state root.

```rust
/// Historic slot instance
pub struct BeaconState {
    ... snip ...

      pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
****  pub latest_execution_payload_header:
          ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,  ****
      pub next_withdrawal_index: WithdrawalIndex,

    ... snip ...
}

/// Historic slot instance
pub struct ExecutionPayloadHeader {
    ... snip ...

      pub base_fee_per_gas: U256,
****  pub block_hash: Hash32,  ****
      pub transactions_root: Root,

    ... snip ...
}
```

##### Generalized Index Constraints

Given `BeaconBlock` Root for slot `n` and some `blockhash` to prove for slot `x` where `CAPELLA_INIT_SLOT <= x < n - 8192`.

|                                     | Merkleized Data Structure                        | Leaf Node                     | Root Node                     | Local Index Constraint(s)                            | Tree Height Constraint |
| ----------------------------------- | ------------------------------------------------ | ----------------------------- | ----------------------------- | ---------------------------------------------------- | ---------------------- |
| `BeaconState` Root Proof            | `BeaconBlock` for slot `n`                       | `BeaconState` Root            | `BeaconBlock` Root            | `LI == 3`                                            | 3                      |
| `HistoricalSummary` Root Proof      | `BeaconState` for slot `n`                       | `state_summary_root`          | `BeaconState` Root            | `LI >= 1811939328`, `LI < 1845493760`, `LI % 2 == 1` | 31                     |
| Historical `BeaconState` Root Proof | `BeaconState` for merkleization slot of slot `n` | Historical `BeaconState` Root | `state_summary_root`          | `LI < 8192`, `LI >= 0`                               | 13                     |
| Blockhash Proof                     | `BeaconState` for slot `x`                       | Historical `blockhash`        | Historical `BeaconState` Root | `LI == 780`                                          | 10                     |

> [!NOTE]
> To learn more about generalized indices, see [this](https://github.com/ethereum/consensus-specs) and [this](https://eth2book.info/capella/annotated-spec/).

### Future Maintenance

As new network upgrades are queued up for release, the structures behind the beacon block root may change. By the nature of SSZ merkleization, this means that the location of data within the tree may change (as discussed [here](#constraining-the-generalized-index)).

The most likely changes are appends to structs. Whenever the amount of fields in a struct crosses over a power of two, the tree height will increase by 1. As such, the tree height will need to be reconfigured and the verifier redeployed. At the time of writing, the Pectra hardfork is queued up for release _and will very likely trigger some tree height changes_.

If the verifier needs to support configurations from multiple incompatible network upgrades, then the verifier will also need to be extended to branch accordingly.

While unlikely, it is also possible that the beacon chain data undergoes a _signficant_ restructuring that throws out the current verifier logic altogether. An example of such a change is the location and scheme in which historical `BeaconState` roots are committed. This is precedented as well since before the Capella hardfork, historical `BeaconState` roots were committed to in the `historical_roots` List; however, post-Capella, they are committed to in the `historical_summaries` List.
