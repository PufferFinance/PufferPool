pragma solidity >=0.8.0 <0.9.0;

import { IERC20 } from "openzeppelin/token/ERC20/IERC20.sol";

contract InsuranceContract {
    IERC20 pufi;

    struct PufiDeposit {
        uint256 amount;
        uint256 unlockDate;
    }

    PufiDeposit[] internal pufiDeposits;
    uint256 public lockedPufi;
    address owner;

    constructor(address _pufi, address _owner) {
        pufi = IERC20(_pufi);
        owner = _owner;
    }

    function deposit(uint256 _numPufi, uint256 _lockupDuration) public {
        require(msg.sender == owner, "Only insurance owner allowed");
        pufi.transferFrom(msg.sender, address(this), _numPufi);
        lockedPufi += _numPufi;
        PufiDeposit memory deposit = PufiDeposit(_numPufi, block.timestamp + _lockupDuration);
        pufiDeposits.push(deposit);
    }

    // TODO: Implement pulling rewards from EL rewards contract
    function pullRewards() public { }

    // TODO: Implement withdrawing pufi from this contract
    function withdraw() public {
        require(msg.sender == owner, "Only insurance owner allowed");
    }
}
