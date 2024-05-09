// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { Permit } from "pufETH/structs/Permit.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { PufferVaultV2 } from "pufETH/PufferVaultV2.sol";
import { ValidatorTicket } from "puffer/ValidatorTicket.sol";
import { Strings } from "openzeppelin-contracts/contracts/utils/Strings.sol";

/**
 *  Replace the `--sender=0xDDDeAfB492752FC64220ddB3E7C9f1d5CcCdFdF0` with the address that will be used to sign the permits and register the validators
 *
 *  To run the simulation:
 *
 *  forge script script/BatchRegisterValidator.s.sol:BatchRegisterValidator --rpc-url=$HOLESKY_RPC_URL --account puffer -vvv --sender=0xDDDeAfB492752FC64220ddB3E7C9f1d5CcCdFdF0
 *
 *  To broadcast the transaction, add `--broadcast` flag at the end of the command
 */
contract BatchRegisterValidator is Script {
    using stdJson for string;

    PufferVaultV2 internal pufETH;
    ValidatorTicket internal validatorTicket;
    address internal protocolAddress;
    string internal registrationJson;

    mapping(bytes32 keyHash => bool registered) internal pubKeys;
    bytes[] internal registeredPubKeys;

    bytes32 private constant _PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    function setUp() public {
        if (block.chainid == 17000) {
            // Holesky
            protocolAddress = 0x705E27D6A6A0c77081D32C07DbDE5A1E139D3F14;
        } else if (block.chainid == 1) {
            // Mainnet
            protocolAddress = 0xf7b6B32492c2e13799D921E84202450131bd238B;
        } else {
            revert("Unsupported chain ID");
        }
    }

    function run() public {
        vm.startBroadcast();

        IPufferProtocol pufferProtocol = IPufferProtocol(protocolAddress);
        pufETH = pufferProtocol.PUFFER_VAULT();
        validatorTicket = pufferProtocol.VALIDATOR_TICKET();

        uint256 guardiansLength = pufferProtocol.GUARDIAN_MODULE().getGuardians().length;

        VmSafe.DirEntry[] memory registrationFiles = vm.readDir("./registration-data");
        require(registrationFiles.length > 0, "No registration files found");

        uint256 vtAmount = vm.promptUint("Enter the VT amount per validator (28 is minimum):");
        require(vtAmount >= 28, "VT amount must be at least 28");

        // Loop 1 to check the number of valid .json files in the directory
        uint256 validFiles = 0;
        for (uint256 i = 0; i < registrationFiles.length; ++i) {
            if (!this.isJsonFile(registrationFiles[i].path)) {
                continue;
            }

            ++validFiles;
        }

        _validateBalances(validFiles, vtAmount);

        require(
            vm.promptUint(
                string.concat(
                    "The directory contains ", Strings.toString(validFiles), " registration files. Enter 1 to proceed"
                )
            ) == 1,
            "User Aborted"
        );

        // Loop 2 to register the validators
        for (uint256 i = 0; i < registrationFiles.length; ++i) {
            if (!this.isJsonFile(registrationFiles[i].path)) {
                console.log("Skipping file: ", registrationFiles[i].path);
                continue;
            }

            registrationJson = vm.readFile(registrationFiles[i].path);

            bytes32 moduleName = stdJson.readBytes32(registrationJson, ".module_name");
            bytes[] memory blsEncryptedPrivKeyShares = new bytes[](guardiansLength);
            blsEncryptedPrivKeyShares[0] = stdJson.readBytes(registrationJson, ".bls_enc_priv_key_shares[0]");

            ValidatorKeyData memory validatorData = ValidatorKeyData({
                blsPubKey: stdJson.readBytes(registrationJson, ".bls_pub_key"),
                signature: stdJson.readBytes(registrationJson, ".signature"),
                depositDataRoot: stdJson.readBytes32(registrationJson, ".deposit_data_root"),
                blsEncryptedPrivKeyShares: blsEncryptedPrivKeyShares,
                blsPubKeySet: stdJson.readBytes(registrationJson, ".bls_pub_key_set"),
                raveEvidence: ""
            });

            Permit memory pufETHPermit = _signPermit({
                to: protocolAddress,
                amount: 2 ether, // Hardcoded to 2 pufETH
                nonce: pufETH.nonces(msg.sender),
                deadline: block.timestamp + 12 hours,
                domainSeparator: pufETH.DOMAIN_SEPARATOR()
            });

            Permit memory vtPermit = _signPermit({
                to: protocolAddress,
                amount: vtAmount * 1 ether, // Upscale to 10**18
                nonce: validatorTicket.nonces(msg.sender),
                deadline: block.timestamp + 12 hours,
                domainSeparator: validatorTicket.DOMAIN_SEPARATOR()
            });

            pubKeys[keccak256(validatorData.blsPubKey)] = true;
            registeredPubKeys.push(validatorData.blsPubKey);

            IPufferProtocol(protocolAddress).registerValidatorKey(validatorData, moduleName, pufETHPermit, vtPermit);
        }

        console.log("Registered PubKeys:");
        console.log("------------------------------------------------------------------------------------------------------------------------");
        for (uint256 i = 0; i < registeredPubKeys.length; ++i) {
            console.logBytes(registeredPubKeys[i]);
        }
    }

    function _validateBalances(uint256 numberOfValidators, uint256 vtBalancePerValidator) internal view {
        uint256 pufETHRequired = pufETH.convertToSharesUp(numberOfValidators * 2 ether);

        if (pufETH.balanceOf(msg.sender) < pufETHRequired) {
            revert("Insufficient pufETH balance");
        }

        uint256 vtRequired = numberOfValidators * vtBalancePerValidator * 1 ether;

        if (validatorTicket.balanceOf(msg.sender) < vtRequired) {
            revert("Insufficient VT balance");
        }
    }

    function _signPermit(address to, uint256 amount, uint256 nonce, uint256 deadline, bytes32 domainSeparator)
        internal
        view
        returns (Permit memory p)
    {
        address operator = msg.sender;
        bytes32 innerHash = keccak256(abi.encode(_PERMIT_TYPEHASH, operator, to, amount, nonce, deadline));
        bytes32 outerHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, innerHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(outerHash);

        return Permit({ deadline: deadline, amount: amount, v: v, r: r, s: s });
    }

    function isJsonFile(string calldata str) external pure returns (bool) {
        uint256 length = bytes(str).length;
        if (length < 5) {
            return false;
        }
        uint256 start = length - 5;
        string memory ext = str[start:];
        // Return true if extension is .json (lowercase)
        return keccak256(abi.encodePacked(ext)) == keccak256(abi.encodePacked(".json"));
    }
}
