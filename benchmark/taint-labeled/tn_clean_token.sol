// @safe transfer
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract P {
    mapping(address=>uint) bal;
    function transfer(address to, uint amt) external {
        require(bal[msg.sender] >= amt, "insufficient");
        bal[msg.sender] -= amt;
        bal[to] += amt;
    }
}
