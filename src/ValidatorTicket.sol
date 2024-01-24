// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { ERC20PermitUpgradeable } from
    "openzeppelin-upgrades/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title ValidatorTicket
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
contract ValidatorTicket is ERC20PermitUpgradeable
{
    using SafeERC20 for address;

    constructor() payable
    {
        _disableInitializers();
    }

    function initialize() external initializer {
        __ERC20Permit_init("ValidatorTicket");
        __ERC20_init("ValidatorTicket", "VT");
    }
}
