// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// These values are the tree heights of the relevant structs. Since the most
// likely changes across hardforks are appends to structs, these heights are
// probably the only fields that could require some configuring. However, a more
// significant change to the beacon chain's data structure could require a logic
// overhaul altogether.

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

/// @dev `BeaconBlockhashVerifier` verifies the integrity of post-Capella
/// blockhashes via SSZ proofs and persists them into the contract's storage.
///
/// This contract uses the entire storage space of the contract as a
/// mapping between `block.number`s and `blockhash`es. Since each number
/// is unique, this is a safe way to store the verified blockhashes.
///
/// This contract is expected to be launched while the Deneb hardfork is active.
contract BeaconBlockhashVerifier {
    struct SszProof {
        bytes32 leaf;
        bytes32[] proof;
    }

    /// @dev The precompile address for SHA-256
    uint256 internal constant SHA256_PRECOMPILE = 0x02;

    /// @dev The address of the EIP-4788 beacon roots contract
    address internal constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @dev Height of the `state_roots` Vector within the BeaconState struct.
    /// This is `log_2(8192)` where 8192 is the `SLOTS_PER_HISTORICAL_ROOT`
    /// constant
    uint256 internal constant STATE_ROOTS_VECTOR_TREE_HEIGHT = 13;

    /// @dev Height of the `historical_summary_roots` List within the
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

    /// @dev Index of `block_number` within the `ExecutionPayload` struct.
    uint256 internal constant BLOCK_NUMBER_LOCAL_INDEX = 6;

    /// @dev Index of `block_hash` within the `ExecutionPayload` struct.
    uint256 internal constant BLOCKHASH_LOCAL_INDEX = 12;

    /// @dev Index of the `state_summary_root` within the `HistoricalSummary`
    /// struct
    uint256 internal constant STATE_SUMMARY_ROOT_LOCAL_INDEX = 1;

    /// @dev Index of the `state_roots` vector within the `BeaconState` struct.
    uint256 internal constant STATE_ROOTS_VECTOR_LOCAL_INDEX = 6;

    /// @dev Index of the `historical_summary_roots` list within the
    /// `BeaconState` struct.
    uint256 internal constant HISTORICAL_SUMMARY_LIST_LOCAL_INDEX = 27;

    /// @dev External call to the beacon roots contract failed.
    error BeaconRootFetchFailed();

    /// @dev Current state root verification failed.
    error InvalidCurrentStateRoot();

    /// @dev Summary root verification failed.
    error InvalidSummaryRoot();

    /// @dev Historical state root verification failed.
    error InvalidHistoricalStateRoot();

    /// @dev Execution payload verification failed.
    error InvalidExecutionPayload();

    /// @dev Block number verification failed.
    error InvalidBlockNumber();

    /// @dev Blockhash verification failed.
    error InvalidBlockhash();

    /// @dev External call to the SHA-256 pre-compile failed.
    error Sha256CallFailed();

    /// @dev The blockhash of the requested `block.number` is not verified.
    error BlockhashNotVerified();

    /// @notice Verifies the integrity of a blockhash for block `x` into the
    /// beacon block root for block `x`.
    ///
    /// @param timestamp The EIP-4788 timestamp.
    /// @param currentStateRootProof The proof from the `BeaconState` root into
    /// the beacon block root.
    /// @param executionPayloadProof The proof from the `ExecutionPayload` root
    /// into the `BeaconState` root.
    /// @param blockNumberProof The proof from the execution payload's block
    /// number into the `ExecutionPayload` root. This is used as the index
    /// during persistence of the verified blockhash.
    /// @param blockhashProof The proof from the execution payload's
    /// blockhash into the `ExecutionPayload` root.
    function verifyCurrentBlock(
        uint256 timestamp,
        SszProof calldata currentStateRootProof,
        SszProof calldata executionPayloadProof,
        SszProof calldata blockNumberProof,
        SszProof calldata blockhashProof
    ) external {
        bytes32 currentSszBlockRoot = _fetchBeaconRoot(timestamp);

        _verifyBeaconStateRoot({ stateRootProof: currentStateRootProof, beaconBlockRoot: currentSszBlockRoot });

        _verifyExecutionPayload({
            executionPayloadProof: executionPayloadProof,
            beaconStateRoot: currentStateRootProof.leaf
        });

        _verifyExecutionBlockNumber({
            blockNumberProof: blockNumberProof,
            executionPayloadRoot: executionPayloadProof.leaf
        });

        _verifyExecutionBlockhash({ blockhashProof: blockhashProof, executionPayloadRoot: executionPayloadProof.leaf });

        _storeVerifiedBlockhash(_parseBeBlockNumber(blockNumberProof.leaf), blockhashProof.leaf);
    }

    /// @notice Verifies the integrity of a blockhash for a block between `x -
    /// 1` and `x - 8192` (where 8192 comes from the `SLOTS_PER_HISTORICAL_ROOT`
    /// constant) into the beacon block root for block `x`.
    ///
    /// @param timestamp The EIP-4788 timestamp.
    /// @param currentStateRootProof The proof from the `BeaconState` root into
    /// the beacon block root.
    /// @param historicalStateRootProof The proof from the historical state root
    /// (within `state_roots` Vector) into the `BeaconState` root.
    /// @param historicalStateRootLocalIndex The local index of the historical
    /// state root (relative to the `BeaconState` root).
    /// @param executionPayloadProof The proof from the `ExecutionPayload` root
    /// into the `BeaconState` root.
    /// @param blockNumberProof The proof from the execution payload's block
    /// number into the `ExecutionPayload` root. This is used as the index
    /// during persistence of the verified blockhash.
    /// @param blockhashProof The proof from the execution payload's
    /// blockhash into the `ExecutionPayload` root.
    function verifyRecentHistoricalBlock(
        uint256 timestamp,
        SszProof calldata currentStateRootProof,
        SszProof calldata historicalStateRootProof,
        uint256 historicalStateRootLocalIndex, // Relative to the `BeaconState` root
        SszProof calldata executionPayloadProof,
        SszProof calldata blockNumberProof,
        SszProof calldata blockhashProof
    ) external {
        bytes32 currentSszBlockRoot = _fetchBeaconRoot(timestamp);

        _verifyBeaconStateRoot({ stateRootProof: currentStateRootProof, beaconBlockRoot: currentSszBlockRoot });

        _verifyHistoricalStateRootIntoBeaconStateRoot({
            historicalStateRootProof: historicalStateRootProof,
            historicalStateRootLocalIndex: historicalStateRootLocalIndex,
            beaconStateRoot: currentStateRootProof.leaf
        });

        _verifyExecutionPayload({
            executionPayloadProof: executionPayloadProof,
            beaconStateRoot: historicalStateRootProof.leaf
        });

        _verifyExecutionBlockNumber({
            blockNumberProof: blockNumberProof,
            executionPayloadRoot: executionPayloadProof.leaf
        });

        _verifyExecutionBlockhash({ blockhashProof: blockhashProof, executionPayloadRoot: executionPayloadProof.leaf });

        _storeVerifiedBlockhash(_parseBeBlockNumber(blockNumberProof.leaf), blockhashProof.leaf);
    }

    /// @notice Verifies the integrity of a blockhash for block between `x -
    /// 8193` and the first Capella block into the beacon block root for block
    /// `x`.
    ///
    /// @param timestamp The EIP-4788 timestamp.
    /// @param currentStateRootProof The proof from the `BeaconState` root into
    /// the beacon block root.
    /// @param summaryRootProof The proof from the historical state summary root
    /// (within the `historical_summaries` List) into the `BeaconState` root.
    /// @param stateSummaryRootLocalIndex The local index of the historical state
    /// summary root (relative to the `BeaconState` root).
    /// @param historicalStateRootProof The proof from the historical state root
    /// (within the `state_roots` Vector) into the historical state summary root.
    /// @param historicalStateRootLocalIndex The local index of the historical
    /// state root (relative to the state summary root).
    /// @param executionPayloadProof The proof from the `ExecutionPayload` root
    /// into the `BeaconState` root.
    /// @param blockNumberProof The proof from the execution payload's block
    /// number into the `ExecutionPayload` root. This is used as the index
    /// during persistence of the verified blockhash.
    /// @param blockhashProof The proof from the execution payload's
    /// blockhash into the `ExecutionPayload` root.
    function verifyHistoricalBlock(
        uint256 timestamp,
        SszProof calldata currentStateRootProof,
        SszProof calldata summaryRootProof,
        uint256 stateSummaryRootLocalIndex, // Relative to the `BeaconState` root
        SszProof calldata historicalStateRootProof,
        uint256 historicalStateRootLocalIndex, // Relative to the state summary root
        SszProof calldata executionPayloadProof,
        SszProof calldata blockNumberProof,
        SszProof calldata blockhashProof
    ) external {
        bytes32 currentSszBlockRoot = _fetchBeaconRoot(timestamp);

        _verifyBeaconStateRoot({ stateRootProof: currentStateRootProof, beaconBlockRoot: currentSszBlockRoot });

        _verifyHistoricalStateSummaryRoot({
            summaryRootProof: summaryRootProof,
            stateSummaryRootLocalIndex: stateSummaryRootLocalIndex,
            beaconStateRoot: currentStateRootProof.leaf
        });

        _verifyHistoricalStateRootIntoStateSummaryRoot({
            historicalStateRootProof: historicalStateRootProof,
            historicalStateRootLocalIndex: historicalStateRootLocalIndex,
            stateSummaryRoot: summaryRootProof.leaf
        });

        _verifyExecutionPayload({
            executionPayloadProof: executionPayloadProof,
            beaconStateRoot: historicalStateRootProof.leaf
        });

        _verifyExecutionBlockNumber({
            blockNumberProof: blockNumberProof,
            executionPayloadRoot: executionPayloadProof.leaf
        });

        _verifyExecutionBlockhash({ blockhashProof: blockhashProof, executionPayloadRoot: executionPayloadProof.leaf });

        _storeVerifiedBlockhash(_parseBeBlockNumber(blockNumberProof.leaf), blockhashProof.leaf);
    }

    /// @dev Verifies a `BeaconState` root into a beacon block root.
    ///
    /// @param stateRootProof The proof from the state root into the beacon
    /// block root.
    /// @param beaconBlockRoot The beacon block root to reconcile the proof
    /// against.
    function _verifyBeaconStateRoot(SszProof calldata stateRootProof, bytes32 beaconBlockRoot) internal view {
        if (
            !_processInclusionProofSha256({
                proof: stateRootProof.proof,
                leaf: stateRootProof.leaf,
                localIndex: STATE_ROOT_LOCAL_INDEX,
                root: beaconBlockRoot,
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
    /// We multiply by `STATE_ROOTS_VECTOR_LOCAL_INDEX` to navigate to the
    /// correct subtree.
    uint256 internal constant STATE_ROOTS_VECTOR_MIN_LOCAL_INDEX =
        STATE_ROOTS_VECTOR_NODES * STATE_ROOTS_VECTOR_LOCAL_INDEX;

    /// @dev Max local index that would be within the `state_roots` vector
    /// (exclusive)
    ///
    /// Just adds the vector capacity
    uint256 internal constant STATE_ROOTS_VECTOR_MAX_LOCAL_INDEX =
        STATE_ROOTS_VECTOR_MIN_LOCAL_INDEX + STATE_ROOTS_VECTOR_NODES;

    /// @dev Verifies a historical state root into the `BeaconState` root.
    ///
    /// @param historicalStateRootProof The proof from the historical state root
    /// into the `BeaconState` root.
    /// @param historicalStateRootLocalIndex The local index of the historical
    /// state root (relative to the `BeaconState` root).
    /// @param beaconStateRoot The `BeaconState` root to reconcile the proof
    /// against.
    function _verifyHistoricalStateRootIntoBeaconStateRoot(
        SszProof calldata historicalStateRootProof,
        uint256 historicalStateRootLocalIndex,
        bytes32 beaconStateRoot
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
                root: beaconStateRoot,
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
    /// fixed whereas Lists can be appended to (with an ever-changing
    /// length). In order to avoid ambiguity in the merklization process,
    /// lengths are mixed in to a List's tree hash.
    uint256 internal constant HR_NODES_PER_S_NODE = 1 << (HISTORICAL_SUMMARY_ROOT_VECTOR_TREE_HEIGHT + 1);

    /// @dev For every node at the layer holding `BeaconState`'s fields, there are
    /// `HSF_NODES_PER_S_NODE` at the layer of the `HistoricalSummary` struct's
    /// fields.
    uint256 internal constant HSF_NODES_PER_S_NODE = HR_NODES_PER_S_NODE << HISTORICAL_SUMMARY_TREE_HEIGHT;

    /// @dev The minimum local index of the `HistoricalSummary` fields (relative
    /// to the `BeaconState` root). We multiply by
    /// `HISTORICAL_SUMMARY_LIST_LOCAL_INDEX` to navigate to the correct
    /// subtree.
    uint256 internal constant HISTORICAL_SUMMARY_FIELDS_LOCAL_INDEX_MIN =
        HSF_NODES_PER_S_NODE * HISTORICAL_SUMMARY_LIST_LOCAL_INDEX;

    /// @dev The number of nodes in the `HistoricalSummary` tree.
    uint256 internal constant HISTORICAL_SUMMARY_TREE_NODES = (1 << HISTORICAL_SUMMARY_TREE_HEIGHT);

    /// @dev The maximum number of `HistoricalSummary` roots that can be
    /// stored in the `historical_summary_roots` vector.
    uint256 internal constant HISTORICAL_SUMMARY_VECTOR_LIMIT = 1 << HISTORICAL_SUMMARY_ROOT_VECTOR_TREE_HEIGHT;

    /// @dev The exclusive maximum local index of the `HistoricalSummary` fields
    /// (relative to the `BeaconState` root).
    uint256 internal constant HISTORICAL_SUMMARY_FIELDS_LOCAL_INDEX_MAX =
        HISTORICAL_SUMMARY_FIELDS_LOCAL_INDEX_MIN + (HISTORICAL_SUMMARY_VECTOR_LIMIT * HISTORICAL_SUMMARY_TREE_NODES);

    /// @dev Add 1 to `HISTORICAL_SUMMARY_ROOT_VECTOR_TREE_HEIGHT` to
    /// account for the length mix-in
    uint256 internal constant HISTORICAL_STATE_SUMMARY_ROOT_PROOF_EXPECTED_HEIGHT =
        STATE_ROOT_TREE_HEIGHT + HISTORICAL_SUMMARY_TREE_HEIGHT + HISTORICAL_SUMMARY_ROOT_VECTOR_TREE_HEIGHT + 1;

    /// @dev Verifies a state summary root into the `BeaconState` root.
    ///
    /// @param summaryRootProof The proof from the state summary root into the
    /// `BeaconState` root.
    /// @param stateSummaryRootLocalIndex The local index of the state summary
    /// root (relative to the `BeaconState` root).
    /// @param beaconStateRoot The `BeaconState` root to reconcile the proof
    /// against.
    function _verifyHistoricalStateSummaryRoot(
        SszProof calldata summaryRootProof,
        uint256 stateSummaryRootLocalIndex, // Relative to the `BeaconState` root
        bytes32 beaconStateRoot
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
                root: beaconStateRoot,
                expectedHeight: HISTORICAL_STATE_SUMMARY_ROOT_PROOF_EXPECTED_HEIGHT
            })
        ) revert InvalidSummaryRoot();
    }

    /// @dev Exclusive maximum local index of the `state_summary_root`
    /// tree. For proving a `state_root` into the `state_summary_root`, the
    /// local index must be less than this value.
    uint256 internal constant STATE_SUMMARY_TREE_MAX_LOCAL_INDEX = 1 << 13;

    /// @dev Verifies a historical state root into its respective state
    /// summary root.
    ///
    /// @param historicalStateRootProof The proof from the historical state root
    /// into the state summary root.
    /// @param historicalStateRootLocalIndex The local index of the historical
    /// state root (relative to the state summary root).
    /// @param stateSummaryRoot The state summary root to reconcile the proof
    /// against.
    function _verifyHistoricalStateRootIntoStateSummaryRoot(
        SszProof calldata historicalStateRootProof,
        uint256 historicalStateRootLocalIndex, // Relative to the state summary root
        bytes32 stateSummaryRoot
    ) internal view {
        // The lower bound on the local index is 0 (which we don't need to
        // explicitly check)
        if (historicalStateRootLocalIndex >= STATE_SUMMARY_TREE_MAX_LOCAL_INDEX) revert InvalidHistoricalStateRoot();

        if (
            !_processInclusionProofSha256({
                proof: historicalStateRootProof.proof,
                leaf: historicalStateRootProof.leaf,
                root: stateSummaryRoot,
                localIndex: historicalStateRootLocalIndex,
                expectedHeight: STATE_ROOTS_VECTOR_TREE_HEIGHT
            })
        ) revert InvalidHistoricalStateRoot();
    }

    /// @dev Verifies an `ExecutionPayload` into the `BeaconState` root
    ///
    /// @param executionPayloadProof The proof from the `ExecutionPayload` root
    /// into the `BeaconState` root.
    /// @param beaconStateRoot The `BeaconState` root to reconcile the proof
    /// against.
    function _verifyExecutionPayload(SszProof calldata executionPayloadProof, bytes32 beaconStateRoot) internal view {
        if (
            !_processInclusionProofSha256({
                proof: executionPayloadProof.proof,
                leaf: executionPayloadProof.leaf,
                root: beaconStateRoot,
                localIndex: EXECUTION_PAYLOAD_LOCAL_INDEX,
                expectedHeight: EXECUTION_PAYLOAD_TREE_HEIGHT
            })
        ) revert InvalidExecutionPayload();
    }

    /// @dev Verifies a block number into an `ExecutionPayload` root
    ///
    /// @param blockNumberProof The proof from the execution payload's block
    /// number into the `ExecutionPayload` root.
    /// @param executionPayloadRoot The `ExecutionPayload` root to reconcile the proof against.
    function _verifyExecutionBlockNumber(SszProof calldata blockNumberProof, bytes32 executionPayloadRoot)
        internal
        view
    {
        if (
            !_processInclusionProofSha256({
                proof: blockNumberProof.proof,
                leaf: blockNumberProof.leaf,
                root: executionPayloadRoot,
                localIndex: BLOCK_NUMBER_LOCAL_INDEX,
                expectedHeight: EXECUTION_PAYLOAD_TREE_HEIGHT
            })
        ) revert InvalidBlockNumber();
    }

    /// @dev Verifies a blockhash into an `ExecutionPayload` root
    ///
    /// @param blockhashProof The proof from the execution payload's blockhash
    /// into the `ExecutionPayload` root.
    /// @param executionPayloadRoot The `ExecutionPayload` root to reconcile the proof against.
    function _verifyExecutionBlockhash(SszProof calldata blockhashProof, bytes32 executionPayloadRoot) internal view {
        if (
            !_processInclusionProofSha256({
                proof: blockhashProof.proof,
                leaf: blockhashProof.leaf,
                root: executionPayloadRoot,
                localIndex: BLOCKHASH_LOCAL_INDEX,
                expectedHeight: EXECUTION_PAYLOAD_TREE_HEIGHT
            })
        ) revert InvalidBlockhash();
    }

    /// @notice Parses a big-endian formatted block number
    /// @dev This only parses the first 6 bytes since a uint48 is enough to
    /// encode a block number.
    ///
    /// @param beBlockNumber The big-endian formatted block number
    /// @return blockNumber The parsed block number
    function _parseBeBlockNumber(bytes32 beBlockNumber) internal pure returns (uint256 blockNumber) {
        /// @solidity memory-safe-assembly
        assembly {
            blockNumber := or(blockNumber, byte(0, beBlockNumber))
            blockNumber := or(blockNumber, shl(8, byte(1, beBlockNumber)))
            blockNumber := or(blockNumber, shl(16, byte(2, beBlockNumber)))
            blockNumber := or(blockNumber, shl(24, byte(3, beBlockNumber)))
            blockNumber := or(blockNumber, shl(32, byte(4, beBlockNumber)))
            blockNumber := or(blockNumber, shl(40, byte(5, beBlockNumber)))
        }
    }

    /// @dev This contract uses the entire storage space of the contract as a
    /// mapping between `block.number`s and `blockhash`es. Since each number
    /// is unique, this is a safe way to store the verified blockhashes.
    ///
    /// @param blockNumber The block number to map the `_blockhash` into
    /// @param _blockhash The blockhash to store
    function _storeVerifiedBlockhash(uint256 blockNumber, bytes32 _blockhash) internal {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(blockNumber, _blockhash)
        }
    }

    /// @notice Checks if a blockhash has been verified
    /// @dev This contract uses the entire storage space of the contract as a
    /// mapping between `block.number`s and `blockhash`es. Since each number
    /// is unique, this is a safe way to store the verified blockhashes.
    ///
    /// REVERTS on unverified `_blockhash`
    ///
    /// @param blockNumber The block number to check
    /// @return _blockhash The blockhash of the block
    function getVerifiedBlockhash(uint256 blockNumber) external view returns (bytes32 _blockhash) {
        /// @solidity memory-safe-assembly
        assembly {
            _blockhash := sload(blockNumber)
        }

        if (_blockhash == 0) revert BlockhashNotVerified();
    }

    /// @dev Processes an inclusion proof with a SHA256 hash.
    ///
    /// In case of an invalid proof length, we return false which is to be
    /// handled by the caller.
    ///
    /// In case of a failed SHA-256 call, we revert.
    ///
    /// @param proof The inclusion proof.
    /// @param leaf The leaf to be proven.
    /// @param root The root to reconcile the proof against.
    /// @param localIndex The local index of the leaf.
    /// @param expectedHeight The height of the tree that the proof is for.
    /// @return valid A boolean indicating whether the derived root from the proof
    /// matches the `root` provided.
    function _processInclusionProofSha256(
        bytes32[] calldata proof,
        bytes32 leaf,
        bytes32 root,
        uint256 localIndex,
        uint256 expectedHeight
    ) internal view returns (bool valid) {
        if (proof.length != expectedHeight) return false;

        /// @solidity memory-safe-assembly
        assembly {
            function callSha256(rdataOffset) {
                if iszero(staticcall(gas(), SHA256_PRECOMPILE, 0x00, 0x40, rdataOffset, 0x20)) {
                    mstore(0x00, 0xcd51ef01) // error Sha256CallFailed()
                    revert(0x1c, 0x04)
                }
            }

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
                    callSha256(0x00)
                    mstore(0x20, calldataload(i))
                }
                default {
                    // Store returndata at 0x20
                    callSha256(0x20)
                    mstore(0x00, calldataload(i))
                }
            }

            callSha256(0x00)
            let derivedRoot := mload(0x00)

            valid := eq(derivedRoot, root)
        }
    }

    /// @dev Fetches the beacon root for a given L1 block timestamp. The
    /// `l1BlockTimestamp` MUST map to an L1 block. The beacon block root
    /// returned will be that of the block's parent.
    ///
    /// @param l1BlockTimestamp The L1 block timestamp.
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
