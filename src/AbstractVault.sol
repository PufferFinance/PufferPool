// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { PufferPool } from "puffer/PufferPool.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { IERC1155Receiver } from "openzeppelin/token/ERC1155/IERC1155Receiver.sol";
import { IERC1155 } from "openzeppelin/token/ERC1155/IERC1155.sol";
import { IERC721Receiver } from "openzeppelin/token/ERC721/IERC721Receiver.sol";
import { IERC721 } from "openzeppelin/token/ERC721/ERC721.sol";

/**
 * @title AbstractVault
 * @notice Inherited by Consensus Pool and ExecutionRewardsPool
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
abstract contract AbstractVault is IERC721Receiver, IERC1155Receiver {
    using SafeTransferLib for address;

    PufferPool public immutable POOL;

    constructor(PufferPool pufferPool) payable {
        POOL = pufferPool;
    }

    /**
     * @notice Transfers all ETH to WithdrawalPool
     */
    function transferETH() external virtual {
        // TODO: authorization?
        POOL.getWithdrawalPool().safeTransferETH(address(this).balance);
    }

    /**
     * @notice Transfers ERC20 `token`'s balance to treasury
     */
    function recoverERC20(address token) external virtual {
        token.safeTransferAll(POOL.TREASURY());
    }

    /**
     * @notice Transfers ERC721 `token` with `tokenId` to treasury
     */
    function recoverERC721(address token, uint256 tokenId) external virtual {
        IERC721(token).safeTransferFrom(address(this), POOL.TREASURY(), tokenId);
    }

    /**
     * @notice Transfers ERC1155 `token` with `tokenId` and `tokenAmount` to treasury
     */
    function recoverERC1155(address token, uint256 tokenId, uint256 tokenAmount) external virtual {
        IERC1155(token).safeTransferFrom(address(this), POOL.TREASURY(), tokenId, tokenAmount, "");
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
