// SPDX-License-Identifier: LicenseRef-VYRN-Research-and-Education-1.0
pragma solidity 0.8.30;

/// Minimal ERC-20 for tests. `feeBps` turns it into a fee-on-transfer token.
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public feeBps;

    function setFee(uint256 bps) external {
        feeBps = bps;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address s, uint256 amount) external returns (bool) {
        allowance[msg.sender][s] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) private {
        balanceOf[from] -= amount;
        balanceOf[to] += amount - amount * feeBps / 10_000;
    }
}
