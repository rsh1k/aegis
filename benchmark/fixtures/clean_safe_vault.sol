/*
 * @source: fixture (intentionally safe — no <yes> markers)
 */
pragma solidity 0.8.24;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
contract SafeVault is Ownable, ReentrancyGuard {
  mapping(address => uint256) private balances;
  event Deposited(address indexed who, uint256 amount);
  event Withdrawn(address indexed who, uint256 amount);
  constructor() Ownable(msg.sender) {}
  function deposit() external payable {
    require(msg.value > 0, "zero");
    balances[msg.sender] += msg.value;
    emit Deposited(msg.sender, msg.value);
  }
  function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "insufficient");
    balances[msg.sender] -= amount;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");
    emit Withdrawn(msg.sender, amount);
  }
}
