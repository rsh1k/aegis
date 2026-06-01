// @expect TAINT-delegatecall-target @ exec
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract P {
    function exec(address t, bytes calldata d) external { t.delegatecall(d); }
}
