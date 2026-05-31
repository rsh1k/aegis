/*
 * @source: SmartBugs Curated (fixture)
 * @vulnerable_at_lines: 9
 */
pragma solidity ^0.4.24;
contract Lottery {
  function pickWinner(uint guess) public view returns (bool) {
    // <yes> <report> BAD_RANDOMNESS
    uint rand = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
    return guess == rand % 100;
  }
}
