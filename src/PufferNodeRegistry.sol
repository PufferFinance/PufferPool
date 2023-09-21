// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

contract PufferNodeRegistry {
    event ValidatorKeyRegistered(address node, bytes pubKey);
    event ValdiatorDequeued(address node, bytes pubKey);

    uint256 currentIndex;

    struct Validator {
        address node;
        bytes pubKey;
    }

    mapping(uint256 => Validator) internal _validatorQueue;

    modifier onlyPufferServiceManager() {
        // require(msg.sender == )
        //todo:
        _;
    }

    function enqueueValidator(address node, bytes calldata pubKey) external onlyPufferServiceManager { }

    function deQueueValidator(address node, uint256 validatorIndex) external onlyPufferServiceManager {
        Validator storage validator = _validatorQueue[validatorIndex];
        if (validator.node == node) {
            emit ValdiatorDequeued(node, validator.pubKey);
            delete validator.node;
            delete validator.pubKey;
        }
    }

    function deQueueAndProvision() external returns (bytes memory) {
        // TODO only guardians

        Validator storage validator = _validatorQueue[currentIndex];

        currentIndex++;

        bytes memory pubKey = validator.pubKey;

        delete validator.node;
        delete validator.pubKey;

        return pubKey;
    }
}
