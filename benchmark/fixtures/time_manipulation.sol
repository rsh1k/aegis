/*
 * @source: SmartBugs Curated (fixture)
 * @vulnerable_at_lines: 8
 */
pragma solidity ^0.4.25;
contract TimedCrowdsale {
  function isSaleFinished() view public returns (bool) {
    // <yes> <report> TIME_MANIPULATION
    return block.timestamp >= 1546300800;
  }
}
