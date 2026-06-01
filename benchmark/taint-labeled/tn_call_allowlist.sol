// @safe forward
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract P {
    mapping(address=>bool) allowed;
    function forward(address to, bytes calldata d) external {
        require(allowed[to], "not allowed");
        to.call(d);
    }
}
