// @expect TAINT-index-write @ _w
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract P {
    mapping(uint=>address) m;
    function setIt(uint k, address v) external { _w(k, v); }
    function _w(uint key, address val) internal { m[key] = val; }
}
