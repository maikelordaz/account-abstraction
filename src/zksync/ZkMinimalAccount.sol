// SPDX-License-Identifier: MIT

pragma solidity 0.8.24;

import {IAccount, ACCOUNT_VALIDATION_SUCCESS_MAGIC} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";
import {Transaction, MemoryTransactionHelper} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/MemoryTransactionHelper.sol";
import {SystemContractsCaller} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/SystemContractsCaller.sol";
import {NONCE_HOLDER_SYSTEM_CONTRACT, BOOTLOADER_FORMAL_ADDRESS} from "lib/foundry-era-contracts/src/system-contracts/contracts/Constants.sol";
import {INonceHolder} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/INonceHolder.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract ZkMinimalAccount is IAccount, Ownable {
    using MemoryTransactionHelper for Transaction;

    error ZkMinimalAccount__NotEnoughBalance();
    error ZkMinimalAccount__NotFromBootloader();

    modifier requireFromBootLoader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS) {
            revert ZkMinimalAccount__NotFromBootloader();
        }
        _;
    }

    constructor() Ownable(msg.sender) {}

    /// @notice must increase the nonce
    /// @notice must validate the transaction (check the owner signed the tx)
    /// @notice check if we have enough balance to pay for the transaction
    function validateTransaction(
        bytes32 /*_txHash*/,
        bytes32 /*_suggestedSignedHash*/,
        Transaction memory _transaction
    ) external payable requireFromBootLoader returns (bytes4 magic) {
        // call(x, y, z) -> Every time the zksync compiler see this and in foundry.toml
        // I have is-system= true it makes a system contract call.
        // Call nonceholder and increment the nonce
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(
                INonceHolder.incrementMinNonceIfEquals,
                (_transaction.nonce)
            )
        );

        // Check fee to pay (here is where we can add a paymaster)
        uint256 totalRequiredBalance = _transaction.totalRequiredBalance();
        if (totalRequiredBalance > address(this).balance) {
            revert ZkMinimalAccount__NotEnoughBalance();
        }

        // Check the signature
        bytes32 txHash = _transaction.encodeHash();
        bytes32 convertedHash = MessageHashUtils.toEthSignedMessageHash(txHash);
        address signer = ECDSA.recover(convertedHash, _transaction.signature);
        bool isValidSigner = signer == owner();
        if (isValidSigner) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }

        return magic;
    }

    function executeTransaction(
        bytes32 _txHash,
        bytes32 _suggestedSignedHash,
        Transaction memory _transaction
    ) external payable {}

    function executeTransactionFromOutside(
        Transaction memory _transaction
    ) external payable {}

    function payForTransaction(
        bytes32 _txHash,
        bytes32 _suggestedSignedHash,
        Transaction memory _transaction
    ) external payable {}

    function prepareForPaymaster(
        bytes32 _txHash,
        bytes32 _possibleSignedHash,
        Transaction memory _transaction
    ) external payable {}
}
