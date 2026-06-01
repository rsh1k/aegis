// @expect TAINT-call-target @ forward
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract P {
    function forward(address to, bytes calldata d) external { to.call(d); }
}
