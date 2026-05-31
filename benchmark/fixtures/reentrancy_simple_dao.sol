/*
 * @source: SmartBugs Curated (fixture)
 * @vulnerable_at_lines: 19
 */
pragma solidity ^0.4.19;
contract SimpleDAO {
  mapping (address => uint) public credit;
  function donate(address to) payable public { credit[to] += msg.value; }
  function withdraw(uint amount) public {
    if (credit[msg.sender] >= amount) {
      // <yes> <report> REENTRANCY
      bool res = msg.sender.call.value(amount)();
      credit[msg.sender] -= amount;
    }
  }
}
