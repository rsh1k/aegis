/*
 * @source: SmartBugs Curated (fixture)
 * @vulnerable_at_lines: 11
 */
pragma solidity ^0.4.24;
contract Unprotected {
  address public owner;
  function Unprotected() public { owner = msg.sender; }
  // <yes> <report> ACCESS_CONTROL
  function setOwner(address newOwner) public { owner = newOwner; }
  function withdraw() public { require(msg.sender == owner); msg.sender.transfer(address(this).balance); }
}
