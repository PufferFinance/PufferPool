// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { IERC1155Receiver } from "openzeppelin/token/ERC1155/IERC1155Receiver.sol";
import { IERC1155 } from "openzeppelin/token/ERC1155/IERC1155.sol";
import { IERC721Receiver } from "openzeppelin/token/ERC721/IERC721Receiver.sol";
import { IERC721 } from "openzeppelin/token/ERC721/ERC721.sol";

/**
 * @title AbstractVault @todo maybe rename to TokenRescue or or something similar?
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
abstract contract AbstractVault is IERC721Receiver, IERC1155Receiver {
    using SafeTransferLib for address;

    /**
     * @notice Thrown when the user is not authorized
     * @dev Signature "0x82b42900"
     */
    error Unauthorized();

    /**
     * @notice Address of the Puffer Protocol
     */
    IPufferProtocol public immutable PUFFER_PROTOCOL;

    constructor(IPufferProtocol pufferProtocol) payable {
        PUFFER_PROTOCOL = pufferProtocol;
    }

    /**
     * @notice Transfers ERC20 `token`'s balance to treasury
     */
    function recoverERC20(address token) external virtual {
        token.safeTransferAll(PUFFER_PROTOCOL.TREASURY());
    }

    /**
     * @notice Transfers ERC721 `token` with `tokenId` to treasury
     */
    function recoverERC721(address token, uint256 tokenId) external virtual {
        IERC721(token).safeTransferFrom(address(this), PUFFER_PROTOCOL.TREASURY(), tokenId);
    }

    /**
     * @notice Transfers ERC1155 `token` with `tokenId` and `tokenAmount` to treasury
     */
    function recoverERC1155(address token, uint256 tokenId, uint256 tokenAmount) external virtual {
        IERC1155(token).safeTransferFrom({
            from: address(this),
            to: PUFFER_PROTOCOL.TREASURY(),
            id: tokenId,
            value: tokenAmount,
            data: ""
        });
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external virtual returns (bytes4) {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        virtual
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function onERC721Received(address, address, uint256, bytes calldata) external virtual returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(AbstractVault).interfaceId;
    }
}
