// @safe setTarget
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract P {
    address owner; address target;
    modifier onlyOwner(){ require(msg.sender==owner); _; }
    function setTarget(address t) external onlyOwner { target = t; }
}
