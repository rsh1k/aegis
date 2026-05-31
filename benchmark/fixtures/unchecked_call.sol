/*
 * @source: SmartBugs Curated (fixture)
 * @vulnerable_at_lines: 9
 */
pragma solidity ^0.4.24;
contract UncheckedReturn {
  function withdraw(address payable to, uint amount) public {
    // <yes> <report> UNCHECKED_LL_CALLS
    to.call.value(amount)("");
  }
}
