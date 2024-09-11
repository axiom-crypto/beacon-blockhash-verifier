// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// These values are the tree heights of the relevant structs. They are the most
// likely to change across hardforks.

/// @dev There are 5 fields in the `BeaconBlock` struct. So this is
/// ceil(log_2(5)).
uint256 constant BLOCK_ROOT_TREE_HEIGHT = 3;

/// @dev There are 2 fields in `HistoricalSummary` struct. So this is
/// log_2(2).
uint256 constant HISTORICAL_SUMMARY_TREE_HEIGHT = 1;

/// @dev There are 28 fields in the `BeaconState` struct. So this is
/// ceil(log_2(28)).
uint256 constant STATE_ROOT_TREE_HEIGHT = 5;

/// @dev There are 17 fields in the `ExecutionPayload` struct. So this is
/// ceil(log_2(17)).
uint256 constant EXECUTION_PAYLOAD_TREE_HEIGHT = 5;

contract BeaconBlockhash {
    struct SszProof {
        bytes32 leaf;
        bytes32[] proof;
    }

    uint256 internal constant SHA256_PRECOMPILE = 0x02;
    address internal constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @dev Height of the `state_roots` vector within the BeaconState struct.
    /// This is `log_2(8192)` where 8192 is the `SLOTS_PER_HISTORICAL_ROOT`
    /// constant
    uint256 internal constant STATE_ROOTS_VECTOR_TREE_HEIGHT = 13;

    /// @dev Height of the `historical_summary_roots` list within the
    /// `BeaconState` struct. This is log_2(16777216) where 16777216 is the
    /// `HISTORICAL_ROOTS_LIMIT` constant
    uint256 internal constant HISTORICAL_SUMMARY_ROOT_VECTOR_TREE_HEIGHT = 24;

    /// @dev Index of `state_root` within the `BeaconBlockHeader` struct.
    ///
    /// struct BeaconBlockHeader {
    ///     pub slot: Slot,
    ///     pub proposer_index: u64,
    ///     pub parent_root: Hash256,
    ///     pub state_root: Hash256,
    ///     pub body_root: Hash256,
    /// }
    ///
    uint256 internal constant STATE_ROOT_LOCAL_INDEX = 3;

    /// @dev Index of `latest_execution_payload_header` within the `BeaconState`
    /// struct.
    uint256 internal constant EXECUTION_PAYLOAD_LOCAL_INDEX = 24;

    /// @dev Index of `block_hash` within the `ExecutionPayload` struct.
    uint256 internal constant BLOCKHASH_LOCAL_INDEX = 12;

    /// @dev Index of the `state_summary_root` within the `HistoricalSummary`
    /// struct
    uint256 internal constant STATE_SUMMARY_ROOT_LOCAL_INDEX = 1;

    /// @dev Index of the `state_roots` vector within the `BeaconState` struct.
    uint256 internal constant STATE_ROOTS_VECTOR_LOCAL_INDEX = 6;

    /// @dev Index of the `historical_summary_roots` list within the `BeaconState` struct.
    uint256 internal constant HISTORICAL_SUMMARY_LIST_LOCAL_INDEX = 27;

    error BeaconRootFetchFailed();

    error InvalidCurrentStateRoot();

    error InvalidSummaryRoot();

    error InvalidHistoricalStateRoot();

    error InvalidBlockhash();

    error Sha256CallFailed();

    /// @param l2BlockTimestamp The timestamp of the L2 block whose l1Origin's
    /// Beacon Block root needs to be fetched.
    /// @param currentStateRootProof The proof from the beacon state root into
    /// the beacon block root.
    /// @param blockhashProof The proof from the execution payload's
    /// blockhash into the beacon state root.
    function verifyCurrentBlock(
        uint256 l2BlockTimestamp,
        SszProof calldata currentStateRootProof,
        SszProof calldata blockhashProof
    ) external {
        bytes32 currentSszBlockRoot = _fetchBeaconRoot(l2BlockTimestamp);

        _verifyBeaconStateRoot({ stateRootProof: currentStateRootProof, root: currentSszBlockRoot });

        _verifyExecutionBlockhash({ blockhashProof: blockhashProof, root: currentStateRootProof.leaf });

        _storeBlockhash(blockhashProof.leaf);
    }

    /// @param l2BlockTimestamp The timestamp of the L2 block whose l1Origin's
    /// Beacon Block root needs to be fetched.
    /// @param currentStateRootProof The proof from the beacon state root into
    /// the beacon block root.
    /// @param historicalStateRootProof The proof from the historical state root
    /// (within `state_roots` Vector) into the beacon state root. The `index`
    /// field should be the generalized index *relative to the beacon state
    /// root*.
    /// @param historicalStateRootLocalIndex The local index of the historical
    /// state root (relative to the beacon state root).
    /// @param blockhashProof The proof from the execution payload's
    /// blockhash into the historical beacon state root.
    function verifyRecentHistoricalBlock(
        uint256 l2BlockTimestamp,
        SszProof calldata currentStateRootProof,
        SszProof calldata historicalStateRootProof,
        uint256 historicalStateRootLocalIndex, // Relative to the beacon state root
        SszProof calldata blockhashProof
    ) external {
        bytes32 currentSszBlockRoot = _fetchBeaconRoot(l2BlockTimestamp);

        _verifyBeaconStateRoot({ stateRootProof: currentStateRootProof, root: currentSszBlockRoot });

        _verifyHistoricalStateRootIntoBeaconStateRoot({
            historicalStateRootProof: historicalStateRootProof,
            historicalStateRootLocalIndex: historicalStateRootLocalIndex,
            root: currentStateRootProof.leaf
        });

        _verifyExecutionBlockhash({ blockhashProof: blockhashProof, root: historicalStateRootProof.leaf });

        _storeBlockhash(blockhashProof.leaf);
    }

    /// @param l2BlockTimestamp The timestamp of the L2 block whose l1Origin's
    /// Beacon Block root needs to be fetched.
    /// @param currentStateRootProof The proof from the beacon state root into
    /// the beacon block root.
    /// @param summaryRootProof The proof from the historical state summary root
    /// (within the `historical_summaries` List) into the beacon state root. The
    /// `index` field should be the generalized index *relative to the beacon
    /// state root*.
    /// @param stateSummaryRootLocalIndex The local index of the historical state
    /// summary root (relative to the beacon state root).
    /// @param historicalStateRootProof The proof from the historical state root
    /// (within the `state_roots` Vector) into the historical state summary root.
    /// The `index` field should be the generalized index *relative to the
    /// state summary root*.
    /// @param historicalStateRootLocalIndex The local index of the historical
    /// state root (relative to the state summary root).
    /// @param blockhashProof The proof from the execution payload's
    /// blockhash into the historical beacon state root.
    function verifyHistoricalBlock(
        uint256 l2BlockTimestamp,
        SszProof calldata currentStateRootProof,
        SszProof calldata summaryRootProof,
        uint256 stateSummaryRootLocalIndex, // Relative to the beacon state root
        SszProof calldata historicalStateRootProof,
        uint256 historicalStateRootLocalIndex, // Relative to the state summary root
        SszProof calldata blockhashProof
    ) external {
        bytes32 currentSszBlockRoot = _fetchBeaconRoot(l2BlockTimestamp);

        _verifyBeaconStateRoot({ stateRootProof: currentStateRootProof, root: currentSszBlockRoot });

        _verifyHistoricalStateSummaryRoot({
            summaryRootProof: summaryRootProof,
            stateSummaryRootLocalIndex: stateSummaryRootLocalIndex,
            root: currentStateRootProof.leaf
        });

        _verifyHistoricalStateRootIntoStateSummaryRoot({
            historicalStateRootProof: historicalStateRootProof,
            historicalStateRootLocalIndex: historicalStateRootLocalIndex,
            root: summaryRootProof.leaf
        });

        _verifyExecutionBlockhash({ blockhashProof: blockhashProof, root: historicalStateRootProof.leaf });

        _storeBlockhash(blockhashProof.leaf);
    }

    /// @dev Verifies a beacon state root into a beacon block root
    function _verifyBeaconStateRoot(SszProof calldata stateRootProof, bytes32 root) internal view {
        if (
            !_processInclusionProofSha256({
                proof: stateRootProof.proof,
                leaf: stateRootProof.leaf,
                localIndex: STATE_ROOT_LOCAL_INDEX,
                root: root,
                expectedHeight: BLOCK_ROOT_TREE_HEIGHT
            })
        ) revert InvalidCurrentStateRoot();
    }

    /// @dev Amount of leaf nodes in the state roots vector tree. Or, another
    /// way to think of it is that every node at the `BeaconState` layer has
    /// `STATE_ROOTS_VECTOR_NODES` amount of child nodes at the layer where
    /// `state_roots` elements are stored.
    uint256 internal constant STATE_ROOTS_VECTOR_NODES = (1 << STATE_ROOTS_VECTOR_TREE_HEIGHT);

    /// @dev Min local index that would be within the `state_roots` vector
    /// (inclusive)
    ///
    /// We multiply by `STATE_ROOTS_VECTOR_LOCAL_INDEX` to nagivate to the
    /// correct subtree.
    uint256 internal constant STATE_ROOTS_VECTOR_MIN_LOCAL_INDEX =
        STATE_ROOTS_VECTOR_NODES * STATE_ROOTS_VECTOR_LOCAL_INDEX;

    /// @dev Max local index that would be within the `state_roots` vector
    /// (exclusive)
    ///
    /// Just adds the vector capacity
    uint256 internal constant STATE_ROOTS_VECTOR_MAX_LOCAL_INDEX =
        STATE_ROOTS_VECTOR_MIN_LOCAL_INDEX + STATE_ROOTS_VECTOR_NODES;

    function _verifyHistoricalStateRootIntoBeaconStateRoot(
        SszProof calldata historicalStateRootProof,
        uint256 historicalStateRootLocalIndex,
        bytes32 root
    ) internal view {
        // Guarantees that the index is within the `state_roots` vector
        if (
            historicalStateRootLocalIndex < STATE_ROOTS_VECTOR_MIN_LOCAL_INDEX
                || historicalStateRootLocalIndex >= STATE_ROOTS_VECTOR_MAX_LOCAL_INDEX
        ) revert InvalidHistoricalStateRoot();

        if (
            !_processInclusionProofSha256({
                proof: historicalStateRootProof.proof,
                leaf: historicalStateRootProof.leaf,
                root: root,
                localIndex: historicalStateRootLocalIndex,
                expectedHeight: STATE_ROOT_TREE_HEIGHT + STATE_ROOTS_VECTOR_TREE_HEIGHT
            })
        ) revert InvalidHistoricalStateRoot();
    }

    /// @dev For every node at the layer holding `BeaconState`'s fields, there are
    /// `hrNodesPerSNode` at the `HistoricalSummary` root layer (note that
    /// the root layer means the layer contains the merklizations of the
    /// `HistoricalSummary` structs, not the fields themselves).
    //
    /// The `+ 1` accounts for the length mix-in. Vectors have their lengths
    /// fixed whereas lists can be appended to (with an ever-changing
    /// length). In order to avoid ambiguity in the merklization process,
    /// lengths are mixed in to a List's tree hash.
    uint256 internal constant HR_NODES_PER_S_NODE = 1 << (HISTORICAL_SUMMARY_ROOT_VECTOR_TREE_HEIGHT + 1);

    /// @dev Amount of nodes in the `historical_summary_roots` vector
    uint256 internal constant HISTORICAL_SUMMARY_ROOT_VECTOR_NODES = 1 << HISTORICAL_SUMMARY_ROOT_VECTOR_TREE_HEIGHT;

    uint256 internal constant HISTORICAL_SUMMARY_VECTOR_LIMIT = 1 << HISTORICAL_SUMMARY_ROOT_VECTOR_TREE_HEIGHT;

    /// @dev For every node at the layer holding `BeaconState`'s fields, there are
    /// `HSF_NODES_PER_S_NODE` at the layer of the `HistoricalSummary` struct's
    /// fields.
    uint256 internal constant HSF_NODES_PER_S_NODE = HR_NODES_PER_S_NODE << HISTORICAL_SUMMARY_TREE_HEIGHT;

    uint256 internal constant HISTORICAL_SUMMARY_FIELDS_LOCAL_INDEX_MIN =
        HSF_NODES_PER_S_NODE * HISTORICAL_SUMMARY_LIST_LOCAL_INDEX;

    uint256 internal constant HISTORICAL_SUMMARY_TREE_NODES = (1 << HISTORICAL_SUMMARY_TREE_HEIGHT);

    uint256 internal constant HISTORICAL_SUMMARY_FIELDS_LOCAL_INDEX_MAX =
        HISTORICAL_SUMMARY_FIELDS_LOCAL_INDEX_MIN + (HISTORICAL_SUMMARY_VECTOR_LIMIT * HISTORICAL_SUMMARY_TREE_NODES);

    /// @dev Add 1 to `HISTORICAL_SUMMARY_ROOT_VECTOR_TREE_HEIGHT` to
    /// account for the length mix-in
    uint256 internal constant HISTORICAL_STATE_SUMMARY_ROOT_PROOF_EXPECTED_HEIGHT =
        STATE_ROOT_TREE_HEIGHT + HISTORICAL_SUMMARY_TREE_HEIGHT + HISTORICAL_SUMMARY_ROOT_VECTOR_TREE_HEIGHT + 1;

    function _verifyHistoricalStateSummaryRoot(
        SszProof calldata summaryRootProof,
        uint256 stateSummaryRootLocalIndex, // Relative to the beacon state root
        bytes32 root
    ) internal view {
        // This check guarantees that the `summaryRootLocalIndex` points to a
        // `state_summary_root`
        if (stateSummaryRootLocalIndex % HISTORICAL_SUMMARY_TREE_NODES != STATE_SUMMARY_ROOT_LOCAL_INDEX) {
            revert InvalidSummaryRoot();
        }

        // This check guarantees that the node at local index
        // `summaryRootLocalIndex` lies within the `historical_summary_roots`
        // vector.
        if (
            stateSummaryRootLocalIndex < HISTORICAL_SUMMARY_FIELDS_LOCAL_INDEX_MIN
                || stateSummaryRootLocalIndex >= HISTORICAL_SUMMARY_FIELDS_LOCAL_INDEX_MAX
        ) revert InvalidSummaryRoot();

        if (
            !_processInclusionProofSha256({
                proof: summaryRootProof.proof,
                leaf: summaryRootProof.leaf,
                localIndex: stateSummaryRootLocalIndex,
                root: root,
                expectedHeight: HISTORICAL_STATE_SUMMARY_ROOT_PROOF_EXPECTED_HEIGHT
            })
        ) revert InvalidSummaryRoot();
    }

    /// @dev Exclusive maximum local index of the `state_summary_root`
    /// tree. For proving a `state_root` into the `state_summary_root`, the GI
    /// must be less than this value.
    uint256 internal constant STATE_SUMMARY_TREE_MAX_LOCAL_INDEX = 1 << 13;

    function _verifyHistoricalStateRootIntoStateSummaryRoot(
        SszProof calldata historicalStateRootProof,
        uint256 historicalStateRootLocalIndex, // Relative to the state summary root
        bytes32 root
    ) internal view {
        // The lower bound on the local index is 0 (which we don't need to
        // explicitly check)
        if (historicalStateRootLocalIndex >= STATE_SUMMARY_TREE_MAX_LOCAL_INDEX) revert InvalidHistoricalStateRoot();

        if (
            !_processInclusionProofSha256({
                proof: historicalStateRootProof.proof,
                leaf: historicalStateRootProof.leaf,
                root: root,
                localIndex: historicalStateRootLocalIndex,
                expectedHeight: STATE_ROOTS_VECTOR_TREE_HEIGHT
            })
        ) revert InvalidHistoricalStateRoot();
    }

    // The `ExecutionPayload` is a field within the `BeaconState` struct.
    // The generalized index here will be calculated relative to the
    // `BeaconState` root.

    /// @dev The amount of nodes at the layer of `ExecutionPayload` fields that are
    /// descendant of each of the nodes at the layer of `BeaconState` fields.
    /// In other words, every node at the `BeaconState` layer has
    /// `E_NODES_PER_S_NODE` child nodes at the `ExecutionPayload` layer.
    uint256 internal constant E_NODES_PER_S_NODE = 1 << EXECUTION_PAYLOAD_TREE_HEIGHT;

    /// @dev Navigate to the subtree that contains the `ExecutionPayload` fields.
    /// (This will be the local index of the first field of
    /// `ExecutionPayload`)
    uint256 internal constant EXECUTION_PAYLOAD_TREE_OFFSET = E_NODES_PER_S_NODE * EXECUTION_PAYLOAD_LOCAL_INDEX;

    /// @dev Navigate to the `block_hash` field within the `ExecutionPayload`
    /// struct. This is the local index *relative to the `BeaconState`
    /// struct*. (`BLOCKHASH_LOCAL_INDEX` is local index relative to
    /// `ExecutionPayload` struct).
    uint256 internal constant BLOCKHASH_B_LOCAL_INDEX = EXECUTION_PAYLOAD_TREE_OFFSET + BLOCKHASH_LOCAL_INDEX;

    /// @dev Verifies a blockhash into a beacon state root
    function _verifyExecutionBlockhash(SszProof calldata blockhashProof, bytes32 root) internal view {
        if (
            !_processInclusionProofSha256({
                proof: blockhashProof.proof,
                leaf: blockhashProof.leaf,
                root: root,
                localIndex: BLOCKHASH_B_LOCAL_INDEX,
                expectedHeight: STATE_ROOT_TREE_HEIGHT + EXECUTION_PAYLOAD_TREE_HEIGHT
            })
        ) revert InvalidBlockhash();
    }

    /// @notice Processes an inclusion proof for a SHA256 hash.
    /// @dev In case of an invalid proof length, we return a garbage hash to
    /// allow the caller to error-handle.
    /// @param proof The inclusion proof
    /// @param leaf The leaf to be proven.
    /// @param localIndex The local index of the leaf.
    /// @param expectedHeight The height of the tree that the proof is for.
    function _processInclusionProofSha256(
        bytes32[] calldata proof,
        bytes32 leaf,
        bytes32 root,
        uint256 localIndex,
        uint256 expectedHeight
    ) internal view returns (bool valid) {
        uint256 length = proof.length;
        if (length != expectedHeight) return false;

        /// @solidity memory-safe-assembly
        assembly {
            switch mod(localIndex, 2)
            case 0 {
                mstore(0x00, leaf)
                mstore(0x20, calldataload(proof.offset))
            }
            default {
                mstore(0x00, calldataload(proof.offset))
                mstore(0x20, leaf)
            }

            // let startOffset := add(proof.offset, 32)
            // But we'll initialize directly in the loop
            let endOffset := add(shl(5, proof.length), proof.offset)
            for { let i := add(proof.offset, 32) } iszero(eq(i, endOffset)) { i := add(i, 32) } {
                // Div by 2
                localIndex := shr(1, localIndex)

                switch mod(localIndex, 2)
                case 0 {
                    // Store returndata at 0x00
                    if iszero(staticcall(gas(), SHA256_PRECOMPILE, 0x00, 0x40, 0x00, 0x20)) {
                        mstore(0x00, 0xcd51ef01) // error Sha256CallFailed()
                        revert(0x1c, 0x04)
                    }
                    mstore(0x20, calldataload(i))
                }
                default {
                    // Store returndata at 0x20
                    if iszero(staticcall(gas(), SHA256_PRECOMPILE, 0x00, 0x40, 0x20, 0x20)) {
                        mstore(0x00, 0xcd51ef01) // error Sha256CallFailed()
                        revert(0x1c, 0x04)
                    }
                    mstore(0x00, calldataload(i))
                }
            }

            if iszero(staticcall(gas(), SHA256_PRECOMPILE, 0x00, 0x40, 0x00, 0x20)) {
                mstore(0x00, 0xcd51ef01) // error Sha256CallFailed()
                revert(0x1c, 0x04)
            }
            let derivedRoot := mload(0x00)

            valid := eq(derivedRoot, root)
        }
    }

    function _storeBlockhash(bytes32 _blockhash) internal {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(_blockhash, 1)
        }
    }

    function readBlockhash(bytes32 _blockhash) external view returns (bool out) {
        /// @solidity memory-safe-assembly
        assembly {
            out := sload(_blockhash)
        }
    }

    /// @notice Fetches the beacon root for a given L1 block timestamp
    /// @param l1BlockTimestamp The L1 block timestamp
    /// @return sszRoot The beacon root belonging to the parent of the block
    /// associated with `l1BlockTimestamp`.
    function _fetchBeaconRoot(uint256 l1BlockTimestamp) internal view returns (bytes32 sszRoot) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, l1BlockTimestamp)
            if iszero(staticcall(gas(), BEACON_ROOTS, 0x00, 0x20, 0x00, 0x20)) {
                mstore(0x00, 0x1aa72f96) // error BeaconRootFetchFailed()
                revert(0x1c, 0x04)
            }
            sszRoot := mload(0x00)
        }
    }
}
