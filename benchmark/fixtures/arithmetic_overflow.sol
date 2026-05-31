/*
 * @source: SmartBugs Curated (fixture)
 * @vulnerable_at_lines: 12
 */
pragma solidity ^0.4.24;
contract IntegerOverflow {
  mapping(address => uint256) public balances;
  function transfer(address to, uint256 value) public {
    require(balances[msg.sender] - value >= 0);
    balances[msg.sender] -= value;
    // <yes> <report> ARITHMETIC
    balances[to] += value;
  }
}
