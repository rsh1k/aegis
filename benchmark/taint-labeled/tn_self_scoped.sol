// @safe deposit
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract P {
    mapping(address=>uint) bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
}
