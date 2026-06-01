// @safe exec
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract P {
    address immutable impl;
    constructor(address a){ impl = a; }
    function exec(bytes calldata d) external { impl.delegatecall(d); }
}
