// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { BeaconBlockhashVerifier } from "../src/BeaconBlockhashVerifier.sol";

import { Solarray } from "solarray/Solarray.sol";

import { Test, stdJson as StdJson } from "forge-std/Test.sol";
import { safeconsole as console } from "forge-std/safeconsole.sol";
import { console2 } from "forge-std/console2.sol";

contract BeaconBlockhashVerifierExposed is BeaconBlockhashVerifier {
    function verifyBeaconStateRoot(SszProof calldata stateRootProof, bytes32 beaconBlockRoot) public view {
        _verifyBeaconStateRoot(stateRootProof, beaconBlockRoot);
    }

    function verifyHistoricalStateRootIntoBeaconStateRoot(
        SszProof calldata historicalStateRootProof,
        uint256 historicalStateRootLocalIndex,
        bytes32 beaconStateRoot
    ) public view {
        _verifyHistoricalStateRootIntoBeaconStateRoot(
            historicalStateRootProof, historicalStateRootLocalIndex, beaconStateRoot
        );
    }

    function verifyHistoricalStateSummaryRoot(
        SszProof calldata summaryRootProof,
        uint256 stateSummaryRootLocalIndex, // Relative to the `BeaconState` root
        bytes32 beaconStateRoot
    ) public view {
        _verifyHistoricalStateSummaryRoot(summaryRootProof, stateSummaryRootLocalIndex, beaconStateRoot);
    }

    function verifyHistoricalStateRootIntoStateSummaryRoot(
        SszProof calldata historicalStateRootProof,
        uint256 historicalStateRootLocalIndex, // Relative to the state summary root
        bytes32 stateSummaryRoot
    ) public view {
        _verifyHistoricalStateRootIntoStateSummaryRoot(
            historicalStateRootProof, historicalStateRootLocalIndex, stateSummaryRoot
        );
    }

    function verifyExecutionPayload(SszProof calldata executionPayloadProof, bytes32 beaconStateRoot) public view {
        _verifyExecutionPayload(executionPayloadProof, beaconStateRoot);
    }

    function verifyExecutionBlockNumber(SszProof calldata blockNumberProof, bytes32 executionPayloadRoot) public view {
        _verifyExecutionBlockNumber(blockNumberProof, executionPayloadRoot);
    }

    function verifyExecutionBlockhash(SszProof calldata blockhashProof, bytes32 beaconStateRoot) public view {
        _verifyExecutionBlockhash(blockhashProof, beaconStateRoot);
    }

    function parseBeBlockNumber(bytes32 beBlockNumber) public pure returns (uint256 blockNumber) {
        return _parseBeBlockNumber(beBlockNumber);
    }

    function processInclusionProofSha256(
        bytes32[] calldata proof,
        bytes32 leaf,
        bytes32 root,
        uint256 localIndex,
        uint256 expectedHeight
    ) internal view returns (bool valid) {
        return _processInclusionProofSha256(proof, leaf, root, localIndex, expectedHeight);
    }

    function fetchBeaconRoot(uint256 timestamp) public view returns (bytes32) {
        return _fetchBeaconRoot(timestamp);
    }
}

contract BeaconBlockhashTest is Test {
    using StdJson for *;

    address internal constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
    BeaconBlockhashVerifierExposed public _beaconBlockhash;

    // The actual root return will be of the parent (9568224)
    uint256 internal constant SLOT_9568225_TIMESTAMP = 1_721_642_723;

    function setUp() public {
        // Block number at which parent of 9568225 is still available
        vm.createSelectFork(vm.envString("RPC_URL_1"), 20_361_365);
        _beaconBlockhash = new BeaconBlockhashVerifierExposed();
    }

    function test_currentBlock() public {
        (
            BeaconBlockhashVerifier.SszProof memory currentStateRootProof,
            BeaconBlockhashVerifier.SszProof memory executionPayloadProof,
            BeaconBlockhashVerifier.SszProof memory blockNumberProof,
            BeaconBlockhashVerifier.SszProof memory blockhashProof
        ) = _loadCurrent("proofs/Current.json");

        console.log(
            "calldata size: ",
            abi.encode(
                SLOT_9568225_TIMESTAMP, currentStateRootProof, executionPayloadProof, blockNumberProof, blockhashProof
            ).length + 4
        );

        _beaconBlockhash.verifyCurrentBlock({
            timestamp: SLOT_9568225_TIMESTAMP,
            currentStateRootProof: currentStateRootProof,
            executionPayloadProof: executionPayloadProof,
            blockNumberProof: blockNumberProof,
            blockhashProof: blockhashProof
        });

        assertEq(
            _beaconBlockhash.getVerifiedBlockhash(_beaconBlockhash.parseBeBlockNumber(blockNumberProof.leaf)),
            blockhashProof.leaf
        );
    }

    function test_recentHistoricalBlock() public {
        (
            BeaconBlockhashVerifier.SszProof memory currentStateRootProof,
            BeaconBlockhashVerifier.SszProof memory historicalStateRootProof,
            uint256 historicalStateRootLocalIndex,
            BeaconBlockhashVerifier.SszProof memory executionPayloadProof,
            BeaconBlockhashVerifier.SszProof memory blockNumberProof,
            BeaconBlockhashVerifier.SszProof memory blockhashProof
        ) = _loadRecentHistorical("proofs/RecentHistorical.json");

        console.log(
            "calldata size: ",
            abi.encode(
                SLOT_9568225_TIMESTAMP,
                currentStateRootProof,
                historicalStateRootProof,
                historicalStateRootLocalIndex,
                executionPayloadProof,
                blockNumberProof,
                blockhashProof
            ).length + 4
        );

        _beaconBlockhash.verifyRecentHistoricalBlock({
            timestamp: SLOT_9568225_TIMESTAMP,
            currentStateRootProof: currentStateRootProof,
            historicalStateRootProof: historicalStateRootProof,
            // historicalStateRootGIndex: 319_232,
            // 319_232 % 2 ** floor(log_2(319_232))
            historicalStateRootLocalIndex: historicalStateRootLocalIndex,
            executionPayloadProof: executionPayloadProof,
            blockNumberProof: blockNumberProof,
            blockhashProof: blockhashProof
        });

        assertEq(
            _beaconBlockhash.getVerifiedBlockhash(_beaconBlockhash.parseBeBlockNumber(blockNumberProof.leaf)),
            blockhashProof.leaf
        );
    }

    function test_historicalBlock() public {
        (
            BeaconBlockhashVerifier.SszProof memory currentStateRootProof,
            BeaconBlockhashVerifier.SszProof memory summaryRootProof,
            uint256 stateSummaryRootLocalIndex,
            BeaconBlockhashVerifier.SszProof memory historicalStateRootProof,
            uint256 historicalStateRootLocalIndex,
            BeaconBlockhashVerifier.SszProof memory executionPayloadProof,
            BeaconBlockhashVerifier.SszProof memory blockNumberProof,
            BeaconBlockhashVerifier.SszProof memory blockhashProof
        ) = _loadHistorical("proofs/Historical.json");

        console.log(
            "calldata size: ",
            abi.encode(
                SLOT_9568225_TIMESTAMP,
                currentStateRootProof,
                summaryRootProof,
                stateSummaryRootLocalIndex,
                historicalStateRootProof,
                historicalStateRootLocalIndex,
                executionPayloadProof,
                blockNumberProof,
                blockhashProof
            ).length + 4
        );

        _beaconBlockhash.verifyHistoricalBlock({
            timestamp: SLOT_9568225_TIMESTAMP,
            currentStateRootProof: currentStateRootProof,
            summaryRootProof: summaryRootProof,
            // summaryRootGIndex: 3_959_423_793,
            // 3_959_423_793 % 2 ** floor(log_2(3_959_423_793))
            stateSummaryRootLocalIndex: stateSummaryRootLocalIndex,
            historicalStateRootProof: historicalStateRootProof,
            // historicalStateRootGIndex: 16_320,
            // 16_320 % 2 ** floor(log_2(16_320))
            historicalStateRootLocalIndex: historicalStateRootLocalIndex,
            executionPayloadProof: executionPayloadProof,
            blockNumberProof: blockNumberProof,
            blockhashProof: blockhashProof
        });

        assertEq(
            _beaconBlockhash.getVerifiedBlockhash(_beaconBlockhash.parseBeBlockNumber(blockNumberProof.leaf)),
            blockhashProof.leaf
        );
    }

    function test_RevertWhen_VerifyBeaconStateRootFails() public {
        (BeaconBlockhashVerifier.SszProof memory stateRootProof,,,) = _loadCurrent("proofs/Current.json");

        vm.expectRevert(BeaconBlockhashVerifier.InvalidCurrentStateRoot.selector);
        _beaconBlockhash.verifyBeaconStateRoot(stateRootProof, bytes32(0));
    }

    function test_RevertWhen_VerifyHistoricalStateRootIntoBeaconStateRootFails() public {
        (, BeaconBlockhashVerifier.SszProof memory historicalStateRootProof, uint256 localIndex,,,) =
            _loadRecentHistorical("proofs/RecentHistorical.json");

        vm.expectRevert(BeaconBlockhashVerifier.InvalidHistoricalStateRoot.selector);
        _beaconBlockhash.verifyHistoricalStateRootIntoBeaconStateRoot(historicalStateRootProof, 0, bytes32(0));

        vm.expectRevert(BeaconBlockhashVerifier.InvalidHistoricalStateRoot.selector);
        _beaconBlockhash.verifyHistoricalStateRootIntoBeaconStateRoot(
            historicalStateRootProof, type(uint256).max, bytes32(0)
        );

        vm.expectRevert(BeaconBlockhashVerifier.InvalidHistoricalStateRoot.selector);
        _beaconBlockhash.verifyHistoricalStateRootIntoBeaconStateRoot(historicalStateRootProof, localIndex, bytes32(0));
    }

    function test_RevertWhen_VerifyHistoricalStateSummaryRootFails() public {
        (, BeaconBlockhashVerifier.SszProof memory summaryRootProof, uint256 localIndex,,,,,) =
            _loadHistorical("proofs/Historical.json");

        vm.expectRevert(BeaconBlockhashVerifier.InvalidSummaryRoot.selector);
        _beaconBlockhash.verifyHistoricalStateSummaryRoot(summaryRootProof, 0, bytes32(0));

        vm.expectRevert(BeaconBlockhashVerifier.InvalidSummaryRoot.selector);
        _beaconBlockhash.verifyHistoricalStateSummaryRoot(summaryRootProof, 1, bytes32(0));

        vm.expectRevert(BeaconBlockhashVerifier.InvalidSummaryRoot.selector);
        _beaconBlockhash.verifyHistoricalStateSummaryRoot(summaryRootProof, type(uint256).max, bytes32(0));

        vm.expectRevert(BeaconBlockhashVerifier.InvalidSummaryRoot.selector);
        _beaconBlockhash.verifyHistoricalStateSummaryRoot(summaryRootProof, localIndex, bytes32(0));
    }

    function test_RevertWhen_VerifyHistoricalStateRootIntoStateSummaryRootFails() public {
        (,,, BeaconBlockhashVerifier.SszProof memory historicalStateRootProof, uint256 localIndex,,,) =
            _loadHistorical("proofs/Historical.json");

        vm.expectRevert(BeaconBlockhashVerifier.InvalidHistoricalStateRoot.selector);
        _beaconBlockhash.verifyHistoricalStateRootIntoStateSummaryRoot(
            historicalStateRootProof, type(uint256).max, bytes32(0)
        );

        vm.expectRevert(BeaconBlockhashVerifier.InvalidHistoricalStateRoot.selector);
        _beaconBlockhash.verifyHistoricalStateRootIntoStateSummaryRoot(historicalStateRootProof, localIndex, bytes32(0));
    }

    function test_RevertWhen_VerifyExecutionPayloadFails() public {
        (, BeaconBlockhashVerifier.SszProof memory executionPayloadProof,,) = _loadCurrent("proofs/Current.json");

        vm.expectRevert(BeaconBlockhashVerifier.InvalidExecutionPayload.selector);
        _beaconBlockhash.verifyExecutionPayload(executionPayloadProof, bytes32(0));
    }

    function test_RevertWhen_VerifyExecutionBlockNumberFails() public {
        (, BeaconBlockhashVerifier.SszProof memory blockNumberProof,,) = _loadCurrent("proofs/Current.json");

        vm.expectRevert(BeaconBlockhashVerifier.InvalidBlockNumber.selector);
        _beaconBlockhash.verifyExecutionBlockNumber(blockNumberProof, bytes32(0));
    }

    function test_RevertWhen_VerifyExecutionBlockhashFails() public {
        (, BeaconBlockhashVerifier.SszProof memory blockhashProof,,) = _loadCurrent("proofs/Current.json");

        vm.expectRevert(BeaconBlockhashVerifier.InvalidBlockhash.selector);
        _beaconBlockhash.verifyExecutionBlockhash(blockhashProof, bytes32(0));
    }

    function test_RevertWhen_FetchingUnverifiedBlockhash() public {
        vm.expectRevert(BeaconBlockhashVerifier.BlockhashNotVerified.selector);
        _beaconBlockhash.getVerifiedBlockhash(0);
    }

    function testFuzz_parseBeBlockNumber(bytes32 beBlockNumber) public view {
        uint256 expectedBlockNumber = 0;
        for (uint256 i = 0; i < 6; i++) {
            expectedBlockNumber |= uint256(uint8(beBlockNumber[i])) << (i * 8);
        }
        assertEq(expectedBlockNumber, _beaconBlockhash.parseBeBlockNumber(beBlockNumber));
    }

    function test_RevertWhen_BeaconRootFetchFails() public {
        vm.expectRevert(BeaconBlockhashVerifier.BeaconRootFetchFailed.selector);
        _beaconBlockhash.fetchBeaconRoot(0);
    }

    function _loadCurrent(string memory path)
        internal
        view
        returns (
            BeaconBlockhashVerifier.SszProof memory currentStateRootProof,
            BeaconBlockhashVerifier.SszProof memory executionPayloadProof,
            BeaconBlockhashVerifier.SszProof memory blockNumberProof,
            BeaconBlockhashVerifier.SszProof memory blockhashProof
        )
    {
        string memory json = vm.readFile(path);
        currentStateRootProof.proof = json.readBytes32Array(".ssz_proof.curr_state_root_proof.branch");
        currentStateRootProof.leaf = json.readBytes32(".ssz_proof.curr_state_root_proof.leaf");

        executionPayloadProof.proof = json.readBytes32Array(".ssz_proof.execution_payload_proof.branch");
        executionPayloadProof.leaf = json.readBytes32(".ssz_proof.execution_payload_proof.leaf");

        blockNumberProof.proof = json.readBytes32Array(".ssz_proof.block_number_proof.branch");
        blockNumberProof.leaf = json.readBytes32(".ssz_proof.block_number_proof.leaf");

        blockhashProof.proof = json.readBytes32Array(".ssz_proof.blockhash_proof.branch");
        blockhashProof.leaf = json.readBytes32(".ssz_proof.blockhash_proof.leaf");
    }

    function _loadRecentHistorical(string memory path)
        internal
        view
        returns (
            BeaconBlockhashVerifier.SszProof memory currentStateRootProof,
            BeaconBlockhashVerifier.SszProof memory historicalStateRootProof,
            uint256 historicalStateRootLocalIndex,
            BeaconBlockhashVerifier.SszProof memory executionPayloadProof,
            BeaconBlockhashVerifier.SszProof memory blockNumberProof,
            BeaconBlockhashVerifier.SszProof memory blockhashProof
        )
    {
        string memory json = vm.readFile(path);
        currentStateRootProof.proof = json.readBytes32Array(".ssz_proof.curr_state_root_proof.branch");
        currentStateRootProof.leaf = json.readBytes32(".ssz_proof.curr_state_root_proof.leaf");

        historicalStateRootProof.leaf = json.readBytes32(".ssz_proof.hist_state_root_proof.leaf");
        historicalStateRootProof.proof = json.readBytes32Array(".ssz_proof.hist_state_root_proof.branch");
        historicalStateRootLocalIndex = json.readUint(".ssz_proof.hist_state_root_proof.local_index");

        executionPayloadProof.proof = json.readBytes32Array(".ssz_proof.execution_payload_proof.branch");
        executionPayloadProof.leaf = json.readBytes32(".ssz_proof.execution_payload_proof.leaf");

        blockNumberProof.proof = json.readBytes32Array(".ssz_proof.block_number_proof.branch");
        blockNumberProof.leaf = json.readBytes32(".ssz_proof.block_number_proof.leaf");

        blockhashProof.proof = json.readBytes32Array(".ssz_proof.blockhash_proof.branch");
        blockhashProof.leaf = json.readBytes32(".ssz_proof.blockhash_proof.leaf");
    }

    function _loadHistorical(string memory path)
        internal
        view
        returns (
            BeaconBlockhashVerifier.SszProof memory currentStateRootProof,
            BeaconBlockhashVerifier.SszProof memory summaryRootProof,
            uint256 stateSummaryRootLocalIndex,
            BeaconBlockhashVerifier.SszProof memory historicalStateRootProof,
            uint256 historicalStateRootLocalIndex,
            BeaconBlockhashVerifier.SszProof memory executionPayloadProof,
            BeaconBlockhashVerifier.SszProof memory blockNumberProof,
            BeaconBlockhashVerifier.SszProof memory blockhashProof
        )
    {
        string memory json = vm.readFile(path);
        currentStateRootProof.proof = json.readBytes32Array(".ssz_proof.curr_state_root_proof.branch");
        currentStateRootProof.leaf = json.readBytes32(".ssz_proof.curr_state_root_proof.leaf");

        summaryRootProof.leaf = json.readBytes32(".ssz_proof.summary_root_proof.leaf");
        summaryRootProof.proof = json.readBytes32Array(".ssz_proof.summary_root_proof.branch");
        stateSummaryRootLocalIndex = json.readUint(".ssz_proof.summary_root_proof.local_index");

        historicalStateRootProof.leaf = json.readBytes32(".ssz_proof.hist_state_root_proof.leaf");
        historicalStateRootProof.proof = json.readBytes32Array(".ssz_proof.hist_state_root_proof.branch");
        historicalStateRootLocalIndex = json.readUint(".ssz_proof.hist_state_root_proof.local_index");

        executionPayloadProof.proof = json.readBytes32Array(".ssz_proof.execution_payload_proof.branch");
        executionPayloadProof.leaf = json.readBytes32(".ssz_proof.execution_payload_proof.leaf");

        blockNumberProof.proof = json.readBytes32Array(".ssz_proof.block_number_proof.branch");
        blockNumberProof.leaf = json.readBytes32(".ssz_proof.block_number_proof.leaf");

        blockhashProof.proof = json.readBytes32Array(".ssz_proof.blockhash_proof.branch");
        blockhashProof.leaf = json.readBytes32(".ssz_proof.blockhash_proof.leaf");
    }
}
