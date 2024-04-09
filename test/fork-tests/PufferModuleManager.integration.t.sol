// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IntegrationTestHelper } from "../helpers/IntegrationTestHelper.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { IRestakingOperator } from "puffer/interface/IRestakingOperator.sol";
import { IPufferModuleManager } from "puffer/interface/IPufferModuleManager.sol";
import { RestakingOperator } from "puffer/RestakingOperator.sol";
import { DeployEverything } from "script/DeployEverything.s.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { ISignatureUtils } from "eigenlayer/interfaces/ISignatureUtils.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IBLSApkRegistry } from "eigenlayer-middleware/interfaces/IRegistryCoordinator.sol";
import { IAVSDirectory } from "eigenlayer/interfaces/IAVSDirectory.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { BN254 } from "eigenlayer-middleware/libraries/BN254.sol";
import { IRegistryCoordinatorExtended } from "puffer/interface/IRegistryCoordinatorExtended.sol";
import { Strings } from "openzeppelin-contracts/contracts/utils/Strings.sol";
import { IERC20 } from "openzeppelin/token/ERC20/IERC20.sol";

interface Weth {
    function deposit() external payable;
}

contract PufferModuleManagerIntegrationTest is IntegrationTestHelper {
    using BN254 for BN254.G1Point;
    using Strings for uint256;

    uint256[] privKeys;
    IBLSApkRegistry.PubkeyRegistrationParams[] pubkeys;

    address EIGEN_DA_REGISTRY_COORDINATOR_HOLESKY = 0x53012C69A189cfA2D9d29eb6F19B32e0A2EA3490;
    address EIGEN_DA_SERVICE_MANAGER = 0xD4A7E1Bd8015057293f0D0A557088c286942e84b;
    IAVSDirectory public avsDirectory = IAVSDirectory(0x055733000064333CaDDbC92763c58BF0192fFeBf);

    function setUp() public {
        deployContractsHolesky(1312190);
    }

    function test_create_puffer_module() public {
        vm.startPrank(DAO);
        pufferProtocol.createPufferModule(bytes32("SOME_MODULE_NAME"));
    }

    function test_opt_into_slashing() public {
        vm.startPrank(DAO);
        IRestakingOperator operator = _createRestakingOperator();

        address slasher = address(1235);

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.RestakingOperatorOptedInSlasher(address(operator), slasher);
        moduleManager.callOptIntoSlashing(operator, slasher);
    }

    function test_modify_operator() public {
        vm.startPrank(DAO);
        IRestakingOperator operator = _createRestakingOperator();

        IDelegationManager.OperatorDetails memory newOperatorDetails = IDelegationManager.OperatorDetails({
            earningsReceiver: address(this),
            delegationApprover: address(0),
            stakerOptOutWindowBlocks: 100
        });

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.RestakingOperatorModified(address(operator), newOperatorDetails);
        moduleManager.callModifyOperatorDetails({ restakingOperator: operator, newOperatorDetails: newOperatorDetails });

        IDelegationManager.OperatorDetails memory details =
            operator.EIGEN_DELEGATION_MANAGER().operatorDetails(address(operator));
        assertEq(details.stakerOptOutWindowBlocks, 100, "updated blocks");

        assertEq(details.earningsReceiver, address(this), "updated earnings");
    }

    function test_update_metadata_uri() public {
        vm.startPrank(DAO);
        IRestakingOperator operator = _createRestakingOperator();

        string memory newUri = "https://puffer.fi/updated.json";

        vm.expectEmit(true, true, true, true);
        emit IPufferModuleManager.RestakingOperatorMetadataURIUpdated(address(operator), newUri);
        moduleManager.callUpdateMetadataURI(operator, newUri);
    }

    function test_register_operator_to_eigen_da() public {
        // 1. Create Restaking Operator contract
        vm.startPrank(DAO);
        IRestakingOperator restakingOperator = _createRestakingOperator();

        // buy weth
        vm.startPrank(0xDDDeAfB492752FC64220ddB3E7C9f1d5CcCdFdF0);
        Weth(0x94373a4919B3240D86eA41593D5eBa789FEF3848).deposit{ value: 500 ether }();
        // deposit into weth strategy
        IStrategyManager(0xdfB5f6CE42aAA7830E94ECFCcAd411beF4d4D5b6).depositIntoStrategy(
            IStrategy(0x80528D6e9A2BAbFc766965E0E26d5aB08D9CFaF9),
            IERC20(0x94373a4919B3240D86eA41593D5eBa789FEF3848),
            500 ether
        );

        ISignatureUtils.SignatureWithExpiry memory signatureWithExpiry;
        IDelegationManager(0xA44151489861Fe9e3055d95adC98FbD462B948e7).delegateTo(
            address(restakingOperator), signatureWithExpiry, bytes32(0)
        );

        // 2. Create EOA operator that will run the AVS, he must have both ECDSA + BLS keypair
        (uint256 privateKey, IBLSApkRegistry.PubkeyRegistrationParams memory params) = _generateOperatorKeys();
        address operatorAddress = vm.addr(privateKey);

        // He signs with his BLS key the message to register him with our Restaking Operator contract
        BN254.G1Point memory messageHash = IRegistryCoordinatorExtended(EIGEN_DA_REGISTRY_COORDINATOR_HOLESKY)
            .pubkeyRegistrationMessageHash(address(restakingOperator));

        params.pubkeyRegistrationSignature = BN254.scalar_mul(messageHash, privateKey);

        (bytes32 digestHash, ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature) =
        _getOperatorSignature(
            privateKey, address(restakingOperator), EIGEN_DA_SERVICE_MANAGER, bytes32("salt"), type(uint256).max
        );

        // 3. Whitelist the operator signature
        vm.startPrank(DAO);
        moduleManager.updateAVSRegistrationSignatureProof(restakingOperator, digestHash, operatorAddress);

        // 4. Dao registers the operator by submitting his signature to the AVS
        moduleManager.callRegisterOperatorToAVS({
            restakingOperator: IRestakingOperator(restakingOperator),
            avsRegistryCoordinator: EIGEN_DA_REGISTRY_COORDINATOR_HOLESKY,
            quorumNumbers: bytes(hex"01"),
            socket: "103.199.107.52:32005;32004",
            params: params,
            operatorSignature: operatorSignature
        });
    }

    // Creates a new restaking operator and returns it
    // metadataURI is used as seed for create2 in EL
    function _createRestakingOperator() internal returns (IRestakingOperator) {
        IRestakingOperator operator = moduleManager.createNewRestakingOperator({
            metadataURI: "https://puffer.fi/metadata.json",
            delegationApprover: address(0),
            stakerOptOutWindowBlocks: 0
        });

        IDelegationManager.OperatorDetails memory details =
            operator.EIGEN_DELEGATION_MANAGER().operatorDetails(address(operator));
        assertEq(details.delegationApprover, address(0), "delegation approver");
        assertEq(details.stakerOptOutWindowBlocks, 0, "blocks");
        assertEq(details.earningsReceiver, address(moduleManager), "earnings receiver");

        return operator;
    }

    function _generateOperatorKeys() internal returns (uint256, IBLSApkRegistry.PubkeyRegistrationParams memory) {
        uint256 privKey = uint256(keccak256(abi.encodePacked("secretPrivateKey")));

        IBLSApkRegistry.PubkeyRegistrationParams memory pubkey;
        pubkey.pubkeyG1 = BN254.generatorG1().scalar_mul(privKey);
        pubkey.pubkeyG2 = _mulGo(privKey);

        return (privKey, pubkey);
    }

    /**
     * @notice internal function for calculating a signature from the operator corresponding to `_operatorPrivateKey`, delegating them to
     * the `operator`, and expiring at `expiry`.
     */
    function _getOperatorSignature(
        uint256 _operatorPrivateKey,
        address operator,
        address avs,
        bytes32 salt,
        uint256 expiry
    ) internal view returns (bytes32 digestHash, ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature) {
        operatorSignature.expiry = expiry;
        operatorSignature.salt = salt;
        {
            digestHash = avsDirectory.calculateOperatorAVSRegistrationDigestHash(operator, avs, salt, expiry);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(_operatorPrivateKey, digestHash);
            operatorSignature.signature = abi.encodePacked(r, s, v);
        }
        return (digestHash, operatorSignature);
    }

    function _mulGo(uint256 x) internal returns (BN254.G2Point memory g2Point) {
        string[] memory inputs = new string[](3);
        inputs[0] = "./test/helpers/go2mul"; // lib/eigenlayer-middleware/test/ffi/go/g2mul.go binary
        inputs[1] = x.toString();

        inputs[2] = "1";
        bytes memory res = vm.ffi(inputs);
        g2Point.X[1] = abi.decode(res, (uint256));

        inputs[2] = "2";
        res = vm.ffi(inputs);
        g2Point.X[0] = abi.decode(res, (uint256));

        inputs[2] = "3";
        res = vm.ffi(inputs);
        g2Point.Y[1] = abi.decode(res, (uint256));

        inputs[2] = "4";
        res = vm.ffi(inputs);
        g2Point.Y[0] = abi.decode(res, (uint256));
    }
}
