// @expect TAINT-selfdestruct-arg @ boom
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract P {
    function boom(address payable to) external { selfdestruct(to); }
}
