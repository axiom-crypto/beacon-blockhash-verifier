# Beacon Blockhash Verifier

A smart contract that verifies the integrity of post-Capella historical `blockhash`es via SSZ proofs. These SSZ proofs are made possible by the introduction of SSZ beacon block roots in [EIP-4788](https://eips.ethereum.org/EIPS/eip-4788).

## Gas and Calldata Benchmarks

#### Gas Report

![image](https://github.com/user-attachments/assets/16349736-1f4f-4769-b3c6-bef644dbcca5)

#### Calldata Size

Valid proofs _should_ have this same calldata size (at least for the Deneb hardfork; reconfiguring the constants could yield a different calldata size).

|                                 | Gas  |
| ------------------------------- | ---- |
| `verifyCurrentBlock()`          | 708  |
| `verifyRecentHistoricalBlock()` | 1444 |
| `verifyHistoricalBlock()`       | 2436 |

## SSZ Proofs

> [!NOTE]
> The following sections assume an understanding of SSZ [Merkleization](https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md).

### Constraining the Generalized Index

As new network upgrades are queued up for release, the structures behind the beacon block root may change. By the nature of SSZ merkleization, this means that the location of data within the tree may change.

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

##### Deriving the Generalized Index Constraint

The local index is constrained to be 3.

The tree height is constrained to be 3 (<code>ceil(log<sub>2</sub>(5))</code>).

<br><br>

Once at the state root, the rest of the segments break down into three separate cases (directly mapping to the three entrypoints of the contract).

#### SSZ beacon block root and blockhash being proven are for the same slot

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

##### Deriving the Generalized Index Constraint

![image](https://github.com/user-attachments/assets/b45ffad8-db4e-469c-82a1-e63e0db41a0b)
![image](https://github.com/user-attachments/assets/2848dc9c-2c8a-4817-9259-feaa50c5c898)

Since this proof is proving into the beacon state root, we will want the local index of node `b` relative to the `BeaconState` tree. We trivially know the local indices of node `ep` relative to the `BeaconState` tree and node `b` relative to the `ExecutionPayload` tree and the tree heights of the `ExecutionPayload` and `BeaconState` trees.

- <code>LI<sub>ep</sub> = 24</code>
- <code>LI<sub>b</sub> = 12</code> (relative to `ExecutionPayload` tree)
- <code>h<sub>bs</sub> = ceil(log<sub>2</sub>(28)) = 5</code>
- <code>h<sub>ep</sub> = ceil(log<sub>2</sub>(17)) = 5</code>

We know that the local index of node `y` in the `BeaconState` tree is 0. There are <code>2<sup>h<sub>ep</sub></sup></code> nodes in each subtree at the level of the execution payload subtree. Another way to think of this is for every node at the layer of the `BeaconState` tree, there are <code>2<sup>h<sub>ep</sub></sup></code> nodes at the layer of the `ExecutionPayload` tree.

To navigate to the local index (relative to the `BeaconState` tree) of the first field of `ExecutionPayload` tree, we do <code>2<sup>h<sub>ep</sub></sup> \* LI<sub>ep</sub></code>.

To navigate to the local index (relative to the `BeaconState` tree) of node `b` of `ExecutionPayload` tree, we do <code>2<sup>h<sub>ep</sub></sup> \* LI<sub>ep</sub> + LI<sub>b</sub></code>.

**So the local index constraint is <code>2<sup>h<sub>ep</sub></sup> \* LI<sub>ep</sub> + LI<sub>b</sub></code>**.

**The tree height constraint is simply <code>h<sub>ep</sub> + h<sub>bs</sub></code>**.

#### SSZ beacon block root is within the past 8192 slots of the blockhash being proven

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

##### Deriving the Generalized Index Constraint

There are two segments whose constraints remain to be derived here. The final segment’s constraints are the same as described [here](#Deriving-the-Generalized-Index-Constraint-1).

![image](https://github.com/user-attachments/assets/90d450c6-d5a2-4d7f-8b75-267967ec2165)

For the second segment, we want to calculate and constrain to a range of LIs (since we want any state root within the vector to be provable). The range of LIs will be leaf nodes in the `StateRoots` tree. They must also be relative to the BeaconState tree.

We trivially know the local index of the `state_roots` vector (relative to the `BeaconState` tree) and the tree heights of the `StateRoots` tree and the `BeaconState` tree.

- <code>LI<sub>sr</sub> = 6</code>
- <code>h<sub>bs</sub> = ceil(log<sub>2</sub>(28)) = 5</code>
- <code>h<sub>sr</sub> = ceil(log<sub>2</sub>(8192)) = 13</code>

We know that the local index of node `y` in the `BeaconState` tree is 0. There are <code>2<sup>h<sub>sr</sub></sup></code> nodes in each subtree at the level of the `state_roots` subtree. Another way to think of this is for every node at the layer of the `BeaconState` tree, there are <code>2<sup>h<sub>sr</sub></sup></code> nodes at the layer of the `StateRoots` tree.

To navigate to the local index (relative to the `BeaconState` tree) of the first element of `StateRoots` tree, we do <code>2<sup>h<sub>sr</sub></sup> \* LI<sub>sr</sub></code>. This is the inclusive lower bound on the LI.

To get the exclusive upper bound we simply have to add the Vector capacity which is <code>2<sup>h<sub>sr</sub></sup></code>.

**So the local index constraint is [<code>2<sup>h<sub>sr</sub></sup> _ LI<sub>sr</sub></code>, <code>2<sup>h<sub>sr</sub></sup> _ LI<sub>sr</sub> + 2<sup>h<sub>sr</sub></sup></code>).**

**The tree height constraint is simply <code>h<sub>sr</sub> + h<sub>bs</sub></code>.**

<br><br>

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

##### Deriving the Generalized Index Constraint

There are three segments for which we will need to derive the constraints (the 2nd - 4th segments).

###### Segment 2

![image](https://github.com/user-attachments/assets/cf1c3fd8-4737-4ab0-96e9-1240ef7f1d85)
![image](https://github.com/user-attachments/assets/4559bb7a-f948-4cd8-9b58-6500c4b25703)

For the second segment, we are provided an LI for an `ssr` node (that is a child of some `r` node). We want to constrain that the respective `r` node is a leaf node in the `HistoricalSummaries` tree. We also want to constrain that the LI refers to a `state_summary_root` (and not some other field in the `HistoricalSummary` struct).

We trivially know:

- <code>LI<sub>hs</sub> = 27</code>: Local index of `historical_summaries` relative to the `BeaconState` tree.
- <code>LI<sub>ssr</sub> = 1</code>: Local index of `state_summary_root` relative to the `HistoricalSummary` tree.
- <code>h<sub>bs</sub> = ceil(log<sub>2</sub>(28)) = 5</code>: Height of the `BeaconState` tree.
- <code>h<sub>hs\*</sub> = ceil(log<sub>2</sub>(16777216)) = 24</code>: Height of the `HistoricalSummaries` List tree.
- <code>h<sub>hs</sub> = ceil(log<sub>2</sub>(2)) = 1</code>: Height of the `HistoricalSummary` tree.

To prove that a supposed `ssr` node is a child of some `r` node that is within the `HistoricalSummaries` List, we will want to prove that the `ssr` node is a child of the merkleization of the `r` nodes (this does NOT include the length mix-in).

We know that the local index of node `y` in the `BeaconState` tree is 0. There are <code>2<sup>h<sub>hs*</sub>+1+h<sub>hs</sub></sup></code> nodes in each subtree at the level of the `HistoricalSummary` struct subtree. Another way to think of this is for every node at the layer of the `BeaconState` tree, there are <code>2<sup>h<sub>hs*</sub>+1+h<sub>hs</sub></sup></code> nodes at the layer of the `HistoricalSummary` struct tree.

To navigate to the local index (relative to the BeaconState tree) of the first field of the first `HistoricalSummary` tree (whose respective `r` node is the first element in the `HistoricalSummaries` tree), we do <code>2<sup>h<sub>hs*</sub>+1+h<sub>hs</sub></sup> * LI<sub>hs</sub></code>. This is the inclusive lower bound on the local index.

To get the upper bound, we add <code>historical*summaries_capacity * 2<sup>hs</sup> = 2<sup>hs\_</sup> \* 2<sup>hs</sup></code> to the lower bound. We multiply by <code>2<sup>hs</sup></code> since the capacity only refers to the quantity of `r` nodes.

Finally, to ensure the local index refers to a `state_summary_root` and not some other field in the struct, we constrain <code>local_index % 2<sup>hs</sup> == LI<sub>ssr</sub></code>.

**So the local index constraints of a given `local_index` are:**

- a) [<code>2<sup>h<sub>hs*</sub>+1+h<sub>hs</sub></sup> * LI<sub>hs</sub></code>, <code>2<sup>h<sub>hs*</sub>+1+h<sub>hs</sub></sup> * LI<sub>hs</sub> + (2<sup>hs*</sup> * 2<sup>hs</sup>)</code>).
- b) <code>local_index % 2<sup>hs</sup> == LI<sub>ssr</sub></code>.

**The tree height constraint is <code>h<sub>bs</sub> + h<sub>hs</sub> + h<sub>hs\*</sub> + 1</code>.**

###### Segment 3

![image](https://github.com/user-attachments/assets/7e765db0-f810-4f54-8dd7-81dd34665a45)

This proof is very simple, and, as a result, so is its LI constraints.

We trivially know the height of the `StateRoots` tree:

- <code>h<sub>sr</sub> = ceil(log<sub>2</sub>(8192)) = 13</code>.

**The local index constraint is [`0`, <code>2<sup>h<sub>sr</sub></sup></code>).**

**The tree height constraint is <code>h<sub>sr</sub></code>.**

###### Segment 4

The constraints for this segment are the same as described [here](#Deriving-the-Generalized-Index-Constraint-1).
