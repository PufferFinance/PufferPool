// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { BaseScript } from "script/BaseScript.s.sol";
import { GuardianModule } from "../src/GuardianModule.sol";
import { PufferProtocol } from "../src/PufferProtocol.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { stdJson } from "forge-std/StdJson.sol";

/**
 * @title Rotate Guardian key and register validators
 * @author Puffer Finance
 * @notice Calls the `depositETH` function on PufferPool
 * @dev Example on how to run the script
 *      forge script script/DeployTestnetValidators.s.sol:DeployTestnetValidators --rpc-url=$RPC_URL --broadcast --sig "run()" -vvvv 
 */
contract DeployTestnetValidators is BaseScript {
    function run() external broadcast {
        string memory pufferDeployment = vm.readFile("./output/puffer.json");
        address payable guardianModule = payable(stdJson.readAddress(pufferDeployment, ".guardianModule"));
        address payable pufferProtocol = payable(stdJson.readAddress(pufferDeployment, ".protocol"));
        
        (bytes memory guardianEnclavePubKey, RaveEvidence memory raveEvidence) = evidence();

        GuardianModule(guardianModule).rotateGuardianKey(
            block.number,
            guardianEnclavePubKey,
            raveEvidence
        );

        // todo register validators
        // PufferProtocol(pufferProtocol).registerValidatorKey(data, moduleName, numberOfDays, pufETHPermit, vtPermit);
    }

    function evidence() internal view returns (bytes memory, RaveEvidence memory) {
        bytes memory guardianEnclavePubKey = hex"04caf1f9cd82a1284626d405d285250fd6c4f58c469fda05d7fd4f29318aae38e7ccc6f4eaced74d3e2aa3fc0576093860d3045263c4183d694a39911ee9031c73";
        bytes memory report = abi.encode(
            "171541400247265784450028677784105405930",
            "2023-10-16T20:13:06.744812",
            "4",
            "EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhspNWPNBkpcmwf+3WZYsuncw6eX6Uijk+PzPp3dBQSebHsOEQYDRxGeFuWowvkTo2Z5HTavyoRIrSupBTqDE78HA=",
            "https://security-center.intel.com",
            "[\"INTEL-SA-00334\",\"INTEL-SA-00615\"]",
            "SW_HARDENING_NEEDED",
            // Already Base64 decoded off-chain
            hex"02000100ac0c00000d000d000000000042616c98d53c9712639447c9b0e7003f0000000000000000000000000000000015150b07ff800e000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000001f000000000000008eb70e76a34bf6cbf9deed7f467b4888cc187f1f1f34cce2d11ca54014149a35000000000000000000000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003af0644b0725449c3def3104fd7428c3ea005f4607e13453d3c05f3aac07b600000000000000000000000000000000000000000000000000000000000000000"
        );

        bytes memory signature =         hex"6cc5a3354c3504677252a3ee19a9d4c64eb8e8ed2bcdd8a7fcfeee88eb8214c0975730b03aeec9b1f56e7cd37030da73b63c8fefb85de1fd2ae70f4d485db8228c76c6dc5da2ce5458c172852d2faec9cca97a1ef4cc19280b84b841e05a7ee33207db18496a3fb515f978ed161d4b7e4c585e76641605be2c31418e04ac35686fa0841b3680d24dac35d8edbfa4c7549b712830b1c0064ae4c0463428ebd0ee833f341fcb2125e9c06d9e67d41f2dc3afe26b1e81d5dbaed1eab6a656e40b9188206f8fdc2745d90db2ebcb671ee44932b9ca7f607c8107bd0c96689bd6aaf9dcdd03afcb433925cacf994527121b79a425a32a86984af5434005b8f422faaa";

        bytes memory signingCert =         hex"308204a130820309a003020102020900d107765d32a3b096300d06092a864886f70d01010b0500307e310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e3130302e06035504030c27496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e67204341301e170d3136313132323039333635385a170d3236313132303039333635385a307b310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e312d302b06035504030c24496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e6730820122300d06092a864886f70d01010105000382010f003082010a0282010100a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040fad6de093511d74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd1ff5b9b864296c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d4244286fcdd4bf64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2dbaf2d42bb7b244f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704cd99598c275e7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af21cc2417061fbd2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484cfc81941e15f55881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666cf76a368978b50203010001a381a43081a1301f0603551d2304183016801478437b76a67ebcd0af7e4237eb357c3b8701513c300e0603551d0f0101ff0404030206c0300c0603551d130101ff0402300030600603551d1f045930573055a053a051864f687474703a2f2f7472757374656473657276696365732e696e74656c2e636f6d2f636f6e74656e742f43524c2f5347582f4174746573746174696f6e5265706f72745369676e696e6743412e63726c300d06092a864886f70d01010b050003820181006708b61b5c2bd215473e2b46af99284fbb939d3f3b152c996f1a6af3b329bd220b1d3b610f6bce2e6753bded304db21912f385256216cfcba456bd96940be892f5690c260d1ef84f1606040222e5fe08e5326808212a447cfdd64a46e94bf29f6b4b9a721d25b3c4e2f62f58baed5d77c505248f0f801f9fbfb7fd752080095cee80938b339f6dbb4e165600e20e4a718812d49d9901e310a9b51d66c79909c6996599fae6d76a79ef145d9943bf1d3e35d3b42d1fb9a45cbe8ee334c166eee7d32fcdc9935db8ec8bb1d8eb3779dd8ab92b6e387f0147450f1e381d08581fb83df33b15e000a59be57ea94a3a52dc64bdaec959b3464c91e725bbdaea3d99e857e380a23c9d9fb1ef58e9e42d71f12130f9261d7234d6c37e2b03dba40dfdfb13ac4ad8e13fd3756356b6b50015a3ec9580b815d87c2cef715cd28df00bbf2a3c403ebf6691b3f05edd9143803ca085cff57e053eec2f8fea46ea778a68c9be885bc28225bc5f309be4a2b74d3a03945319dd3c7122fed6ff53bb8b8cb3a03c";

        return (guardianEnclavePubKey, RaveEvidence({
            report: report,
            signature: signature,
            leafX509CertDigest: keccak256(signingCert)
        }));
    }
}
