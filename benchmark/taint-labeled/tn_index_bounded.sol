// @safe setIt
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract P {
    mapping(uint=>address) m;
    function setIt(uint k, address v) external {
        require(k < 100, "oob");
        m[k] = v;
    }
}
