// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "./SimpleAccount.sol";

/**
 * A sample factory contract for SimpleAccount
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory).
 * The factory's createAccount returns the target account address even if it is already installed.
 * This way, the entryPoint.getSenderAddress() can be called either before or after the account is created.
 */
contract SimpleAccountFactory {
    SimpleAccount public immutable accountImplementation;

    mapping(uint256 => address) public AddressOf;
    error NameExists(uint256 name);

    constructor(IEntryPoint _entryPoint) {
        accountImplementation = new SimpleAccount(_entryPoint);
    }

    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation
     */
    function createAccount(
        address owner,
        uint256 name
    ) public returns (SimpleAccount ret) {
        address addr = _getAddress(owner, name);
        address fromMapping = AddressOf[name];

        if (fromMapping != address(0) && addr == fromMapping) {
            return SimpleAccount(payable(fromMapping));
        }
        // The SimpleAccount for "name" is deployed for another owner, duplicate names are not allowed
        else if (fromMapping != address(0) && addr != fromMapping) {
            revert NameExists(name);
        }
        // The input "name" is not deployed before
        else {
            uint256 codeSize = addr.code.length;
            if (codeSize > 0) {
                return SimpleAccount(payable(addr));
            }
            ret = SimpleAccount(
                payable(
                    new ERC1967Proxy{salt: bytes32(name)}(
                        address(accountImplementation),
                        abi.encodeCall(SimpleAccount.initialize, (owner))
                    )
                )
            );
            AddressOf[name] = addr;
        }
    }

    function _getAddress(
        address owner,
        uint256 name
    ) private view returns (address) {
        return
            Create2.computeAddress(
                bytes32(name),
                keccak256(
                    abi.encodePacked(
                        type(ERC1967Proxy).creationCode,
                        abi.encode(
                            address(accountImplementation),
                            abi.encodeCall(SimpleAccount.initialize, (owner))
                        )
                    )
                )
            );
    }

    function getAddress(
        address owner,
        uint256 name
    ) external view returns (address) {
        address addr = _getAddress(owner, name);
        address fromMapping = AddressOf[name];
        if (fromMapping != address(0) && addr != fromMapping) {
            revert NameExists(name);
        }

        return _getAddress(owner, name);
    }
}
