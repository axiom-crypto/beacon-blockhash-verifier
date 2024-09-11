// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { BeaconBlockhash } from "../src/BeaconBlockhash.sol";

import { Solarray } from "solarray/Solarray.sol";

import { Test } from "forge-std/Test.sol";
import { safeconsole as console } from "forge-std/safeconsole.sol";
import { console2 } from "forge-std/console2.sol";

contract BeaconBlockhashTest is Test {
    address internal constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
    BeaconBlockhash public _beaconBlockhash;

    // The actual root return will be of the parent (9568224)
    uint256 internal constant SLOT_9568225_TIMESTAMP = 1_721_642_723;

    bytes32[] currentStateRootProof = Solarray.bytes32s(
        0x1d0e66c14b2df6a592e348ff1a785f6a1da4d3bff3f03b1c37706adf4b9c60d2,
        0x63927d5d06977fc159fb1a023208e97ae3b11ef4d9049209ba2dd1fdf6df5553,
        0xe50667bec9fe6f0f2c93e55ec51f1e42e427f6894ce13ff3f2bb5a783c59ae7a
    );

    BeaconBlockhash.SszProof _currentStateRootProof = BeaconBlockhash.SszProof({
        leaf: 0x5b5b58c88c8bca6a8c3901892e2dfded3ead0a67602cecb9dc0fa2fc4cc7984e,
        proof: currentStateRootProof
    });

    function setUp() public {
        // Block number at which parent of 9568225 is still available
        vm.createSelectFork(vm.envString("RPC_URL_1"), 20_361_365);
        _beaconBlockhash = new BeaconBlockhash();
    }

    function test_currentBlock() public {
        bytes32[] memory blockhashProof = new bytes32[](10);
        blockhashProof[0] = 0x98907ff2db2d8d736b264c942acfa577abe1fade84ba5aa0452ada7c92724c10;
        blockhashProof[1] = 0x01518d7ada184505cac9b357524a82ff896d010980c97206cd0428825cecc378;
        blockhashProof[2] = 0x352afee35170f2a33c1a77219c35e651c54b389fed8c4246bf20d01efaf57bd8;
        blockhashProof[3] = 0x8d81d69fd3e4479b64c973aabec7ce7018e1fc0473ce187b60ebaef821cdc769;
        blockhashProof[4] = 0xb9ce8de979e8b7148e3950f9e8cb273220e04e309a598125d05b7d7f85544378;
        blockhashProof[5] = 0xeb1b2c0300000000000000000000000000000000000000000000000000000000;
        blockhashProof[6] = 0x7a635f6b5c96574d4a4eda40e63602947682cc7584271d26eab500b62f4e54bf;
        blockhashProof[7] = 0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71;
        blockhashProof[8] = 0x7529dfe4f3504264983ceb4c11cd3869c52a6384491d3f09315a5404656f534b;
        blockhashProof[9] = 0x026a4f79435a63b7e343a74608d99a553dea104cb3027a9645f3eed567aedd8e;

        BeaconBlockhash.SszProof memory _blockhashProof = BeaconBlockhash.SszProof({
            leaf: 0x1dfaf76d5bcf603cfa38b9fdd791e1a14c3701d0468b84f4bf6b7cf4c260525e,
            proof: blockhashProof
        });

        console.log(
            "calldata size: ", abi.encode(SLOT_9568225_TIMESTAMP, _currentStateRootProof, _blockhashProof).length + 4
        );

        _beaconBlockhash.verifyCurrentBlock({
            l2BlockTimestamp: SLOT_9568225_TIMESTAMP,
            currentStateRootProof: _currentStateRootProof,
            blockhashProof: _blockhashProof
        });

        assertEq(_beaconBlockhash.readBlockhash(_blockhashProof.leaf), true);
    }

    function test_recentHistoricalBlock() public {
        bytes32[] memory historicalStateRootProof = new bytes32[](18);
        historicalStateRootProof[0] = 0xf3b26bb5fa9309addbd2189a6cb12327c9f6f0b1790642e1f0a3bc3c2ffb50f5;
        historicalStateRootProof[1] = 0x5f1e9374170f164e17faf8f1e47f13ee9c3133ad82b7efcfbdb09cf3c2452f05;
        historicalStateRootProof[2] = 0xb79dbb601d18a23e78c2319f77e3de9dcc423497f93a3ee225cfcc2ffdb44576;
        historicalStateRootProof[3] = 0x1f34c60f224c82fdcd4343dafc705abc3b897f1f4fb2cbb90c0cac52217bf231;
        historicalStateRootProof[4] = 0x77a723f00b215d6624aaa003143273d42544b390d37f140a13ed736d99f3e9ef;
        historicalStateRootProof[5] = 0xc4975e6f003f538bb3fea57ac716dba98b3dcae3859f59516598d8d6d1387b5d;
        historicalStateRootProof[6] = 0xd83d8d459c2ff1d8392ecb1b31c04dd77ff0b962621de122943d71c40b6e0b1d;
        historicalStateRootProof[7] = 0xa23eba85b51c844fde72c2ddba605c0f8ef26f4ea6899d0756a9b58a251c7699;
        historicalStateRootProof[8] = 0xd578cc8bbaba433cd7e0ff846e30ce6576c0f1309c9b88b6d3849cc479fae612;
        historicalStateRootProof[9] = 0x117e9e9557939b396f3b01b0131360d5f45604ff030d721b9c493d5d520149c1;
        historicalStateRootProof[10] = 0x9a2839467f7685b8b95fa66d792a4719a69926857a245e3acacf07dd37d53db5;
        historicalStateRootProof[11] = 0xcf1adf5c6f922870a89fe4abea4dddee2134f07a07367cc65b74c9bd4d5f83ca;
        historicalStateRootProof[12] = 0x7f95247c564a48f1a2b6f321e5a80ae7655b1c4e76caf843a00b04b6f7675511;
        historicalStateRootProof[13] = 0x4df6b89755125d4f6c5575039a04e22301a5a49ee893c1d27e559e3eeab73da7;
        historicalStateRootProof[14] = 0x7a8d34f693bf69ef45732cd264c84b56b4f64175103dec8a5b7c94bc0eab9308;
        historicalStateRootProof[15] = 0x1d89457667c3810985cc35772d3bfe901c648918c36bbff3ca5c26f0196e10a2;
        historicalStateRootProof[16] = 0xee3387c6aca70e9bbb7cd7baefb22b21ccacbe053fa003c079abfaf9bc7383b7;
        historicalStateRootProof[17] = 0x7c8caa41654e3a73f0f4c5a1ad7410dadd02f83b0a24da90a18cec3c5bbf37e8;

        bytes32[] memory blockhashProof = new bytes32[](10);
        blockhashProof[0] = 0xd40f7f334f2f0cfac3fcfe4cbd9ef399f4550d70a3864024c884886a15ef26e2;
        blockhashProof[1] = 0x59d1cd533253cd8879842dcd842b097cab2060750a88f50714bc541cf00edfb8;
        blockhashProof[2] = 0x866af279d44595cab607a1332426fcb127326102c795b0e3f281027c8bef8978;
        blockhashProof[3] = 0x4d444478b8416a735bfcd11f0c4fdbc9ce8ea8f5284b43d7603a6d51a6f04178;
        blockhashProof[4] = 0x0c0b3c320c5dbeb31f092c54aaab8e0d280a5252d351416466804c51d843cbc5;
        blockhashProof[5] = 0xfb0d2c0300000000000000000000000000000000000000000000000000000000;
        blockhashProof[6] = 0x109f1ebb3754a553f8372252bf6d7c962ef7a537bf5134530bb60593bca1eddf;
        blockhashProof[7] = 0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71;
        blockhashProof[8] = 0xa3a11facbf1d484b0ea149f901d9e563d512e15093c4b00231af68eb1e06e9db;
        blockhashProof[9] = 0x81587d91af22f2bee1f7840d06d5403c3132674c9ea3e9dceb8fc49384490369;

        BeaconBlockhash.SszProof memory _historicalStateRootProof = BeaconBlockhash.SszProof({
            leaf: 0x7688551bb6747dc6a456a7254af5a96b6d6b1f0e6dcb1b73a9f5fd7bceaaa704,
            proof: historicalStateRootProof
        });

        BeaconBlockhash.SszProof memory _blockhashProof = BeaconBlockhash.SszProof({
            leaf: 0x41b7ee50ec947f08156d9bddbaf5e5b21de9998e6dc2a53ec7f5a82bf4c9878c,
            proof: blockhashProof
        });

        console.log(
            "calldata size: ",
            abi.encode(
                SLOT_9568225_TIMESTAMP, _currentStateRootProof, _historicalStateRootProof, 57_088, _blockhashProof
            ).length + 4
        );

        _beaconBlockhash.verifyRecentHistoricalBlock({
            l2BlockTimestamp: SLOT_9568225_TIMESTAMP,
            currentStateRootProof: _currentStateRootProof,
            historicalStateRootProof: _historicalStateRootProof,
            // historicalStateRootGIndex: 319_232,
            // 319_232 % 2 ** floor(log_2(319_232))
            historicalStateRootLocalIndex: 57_088,
            blockhashProof: _blockhashProof
        });

        assertEq(_beaconBlockhash.readBlockhash(_blockhashProof.leaf), true);
    }

    function test_historicalBlock() public {
        bytes32[] memory summaryRootProof = new bytes32[](31);
        summaryRootProof[0] = 0xd30b7ab14521d9a3ff9873a052a3da7778c9362317c4a9f73e3ca8ce9154789c;
        summaryRootProof[1] = 0x0000000000000000000000000000000000000000000000000000000000000000;
        summaryRootProof[2] = 0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b;
        summaryRootProof[3] = 0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71;
        summaryRootProof[4] = 0x5a0d881fa31f37c1ce162a4ddc54cbd9ac6e8d115c86f3a242eb131e071512e9;
        summaryRootProof[5] = 0x782cf737bc50eccde614a3d336a2ee6295c89dabe6887f78b8d345eea3dc1a48;
        summaryRootProof[6] = 0x9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30;
        summaryRootProof[7] = 0xd88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1;
        summaryRootProof[8] = 0x824dfe0e3b5770995756d697ad340379726df273846bd11b4c2cfba106823f65;
        summaryRootProof[9] = 0x460485af574848585860d57ea2bd50835e0b5a2a296e0dcb014483c82debb54f;
        summaryRootProof[10] = 0x506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1;
        summaryRootProof[11] = 0xffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b;
        summaryRootProof[12] = 0x6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220;
        summaryRootProof[13] = 0xb7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f;
        summaryRootProof[14] = 0xdf6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e;
        summaryRootProof[15] = 0xb58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784;
        summaryRootProof[16] = 0xd49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb;
        summaryRootProof[17] = 0x8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb;
        summaryRootProof[18] = 0x8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab;
        summaryRootProof[19] = 0x95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4;
        summaryRootProof[20] = 0xf893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f;
        summaryRootProof[21] = 0xcddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa;
        summaryRootProof[22] = 0x8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c;
        summaryRootProof[23] = 0xfeb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167;
        summaryRootProof[24] = 0xe71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7;
        summaryRootProof[25] = 0x9901000000000000000000000000000000000000000000000000000000000000;
        summaryRootProof[26] = 0xcb9a130000000000000000000000000000000000000000000000000000000000;
        summaryRootProof[27] = 0xd25bc7f07250c3bcbbce5b1e4e23d20715982d1e4cc0e38bd8d2da5d18cba654;
        summaryRootProof[28] = 0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71;
        summaryRootProof[29] = 0x7529dfe4f3504264983ceb4c11cd3869c52a6384491d3f09315a5404656f534b;
        summaryRootProof[30] = 0x026a4f79435a63b7e343a74608d99a553dea104cb3027a9645f3eed567aedd8e;

        bytes32[] memory historicalStateRootProof = new bytes32[](13);
        historicalStateRootProof[0] = 0x4882fd44f01d5f75de72a93b33648a8528005fb0e409e1c012757e34a2ef69cc;
        historicalStateRootProof[1] = 0xe4f64a168fe1aa3ea666d7401bfa20527b08aee6ceb4ede2852348e4ec19a80a;
        historicalStateRootProof[2] = 0x10e8b9f45d0cc2fcc622068d65c53f310e94443cb7450931b6792df3cfd1c30a;
        historicalStateRootProof[3] = 0xb9ed6ef91a14dd0b7aadae3d390b70065eb637e17d474267a264973d53f572d9;
        historicalStateRootProof[4] = 0x8df886ba0f4c4a4c937b7c289cc09a98453f7078a883f406c26b2d355d2aed41;
        historicalStateRootProof[5] = 0x51a3f2586eabcc4c829aa474b5c0c4a19ffd10ded9f1c106bfd533580a2a218c;
        historicalStateRootProof[6] = 0xc0f65e5e76b634ef47860b40916b2ec9dacd755ef62d1ccfbb7ace2f887150ea;
        historicalStateRootProof[7] = 0x49091602a3fb08061dd97bf4ff89f33a0569c69db8abcb569f7e0a5418dd5a83;
        historicalStateRootProof[8] = 0xa4658debd96bd00d6625c8ca1c5672607dd3543f007416a8ae33de79fa3e03a2;
        historicalStateRootProof[9] = 0xc6e52045b5925e7e09ecef2d6d3f15b5d8bf59b324c7fb666f74dee4accd435b;
        historicalStateRootProof[10] = 0x4f745be73399d9752df8954e5afe30c80f1860df6218705e0b4b251d018e93f4;
        historicalStateRootProof[11] = 0x1f7325ec65a54c6e6b413845ea38dbda1974d8966eda7de95dcc4ad8d4b676d1;
        historicalStateRootProof[12] = 0xc8ce7af253f68b9cadea80165571ec410d17a366281bacd052972d99fc0c5fcb;

        bytes32[] memory blockhashProof = new bytes32[](10);
        blockhashProof[0] = 0x20d6f4e6356bc159b368341627ac77e06d831f4a86d0691cb15ac6512eeef662;
        blockhashProof[1] = 0x31ff5fb7f6606c72dd7f8db7f47af00edaff95cf829adcbb93b7e263a9f517de;
        blockhashProof[2] = 0x178fb3a7402845508c4c141bacec3bfd7961f7206f7588448c7d07b3956b9214;
        blockhashProof[3] = 0x2bdb838c7a4806dfd1fe2b2769cec1c79e4bf7d3833f06e952536ffcd056cfaf;
        blockhashProof[4] = 0x2a36e25ced18cdb69e1560a10f42aec4acd87e7661ff35501380e212b10e0e62;
        blockhashProof[5] = 0xab1c2a0300000000000000000000000000000000000000000000000000000000;
        blockhashProof[6] = 0x744f502e6194c14330052d704bfafa60925bf00d8a2f1568e14e365f6ca63be1;
        blockhashProof[7] = 0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71;
        blockhashProof[8] = 0xb9116d75914722f1c89cf2bd51b11bd3167615abc265408e00822166d158b5c9;
        blockhashProof[9] = 0x51b7c46c28d41aa08cb77b8514cc413f37105d6e325095b8e06003721775da11;

        BeaconBlockhash.SszProof memory _summaryRootProof = BeaconBlockhash.SszProof({
            leaf: 0xf4d009882fd5e34e2b235bb8e1727ef3a16a0797244ee209b14a7402db5cf0fc,
            proof: summaryRootProof
        });

        BeaconBlockhash.SszProof memory _historicalStateRootProof = BeaconBlockhash.SszProof({
            leaf: 0xfd22b356591114ba21745e976f81a97bfefbfe9839d17e01adae77cc02c7268f,
            proof: historicalStateRootProof
        });

        BeaconBlockhash.SszProof memory _blockhashProof = BeaconBlockhash.SszProof({
            leaf: 0x4e64288844f3ecd1994862146b90c0dda41822eaf845a5f4501ec1da028383a8,
            proof: blockhashProof
        });

        console.log(
            "calldata size: ",
            abi.encode(
                SLOT_9568225_TIMESTAMP,
                _currentStateRootProof,
                _summaryRootProof,
                1_811_940_145,
                _historicalStateRootProof,
                8128,
                _blockhashProof
            ).length + 4
        );

        _beaconBlockhash.verifyHistoricalBlock({
            l2BlockTimestamp: SLOT_9568225_TIMESTAMP,
            currentStateRootProof: _currentStateRootProof,
            summaryRootProof: _summaryRootProof,
            // summaryRootGIndex: 3_959_423_793,
            // 3_959_423_793 % 2 ** floor(log_2(3_959_423_793))
            stateSummaryRootLocalIndex: 1_811_940_145,
            historicalStateRootProof: _historicalStateRootProof,
            // historicalStateRootGIndex: 16_320,
            // 16_320 % 2 ** floor(log_2(16_320))
            historicalStateRootLocalIndex: 8128,
            blockhashProof: _blockhashProof
        });

        assertEq(_beaconBlockhash.readBlockhash(_blockhashProof.leaf), true);
    }
}
