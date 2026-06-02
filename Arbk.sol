// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title ARBK Token
 * @dev Arbitrum native token implementation
 * This token is designed for use on Arbitrum L2 with optimized gas usage
 */
contract ARBK is ERC20, Ownable2Step, ReentrancyGuard {
    // Events
    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);
    event Pause();
    event Unpause();
    
    // Constants
    string private constant _NAME = "Arbitrum Kernel";
    string private constant _SYMBOL = "ARBK";
    uint8 private constant _DECIMALS = 18;
    uint256 private constant _MAX_SUPPLY = 100_000_000 * 10**uint256(_DECIMALS); // 100M tokens max
    
    // State variables
    bool private _paused;
    mapping(address => bool) private _blacklisted;
    
    // Custom errors
    error InvalidAmount();
    error InsufficientBalance();
    error Paused();
    error NotPaused();
    error BlacklistedAddress();
    error MaxSupplyExceeded();
    error InvalidRecipient();
    
    /**
     * @dev Constructor initializes the token with initial supply and owner
     * @param initialOwner The address that will own this contract
     * @param initialSupply The initial supply to mint (must be <= max supply)
     */
    constructor(
        address initialOwner,
        uint256 initialSupply
    ) ERC20(_NAME, _SYMBOL) {
        if (initialSupply > _MAX_SUPPLY) {
            revert MaxSupplyExceeded();
        }
        
        _mint(msg.sender, initialSupply);
        _transferOwnership(initialOwner);
        _paused = false;
    }
    
    /**
     * @dev Mints new tokens to a specified address
     * @param to The address to mint tokens to
     * @param amount The amount of tokens to mint
     * @notice Only owner can call this function
     * @notice Can only mint up to max supply
     */
    function mint(address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) {
            revert InvalidRecipient();
        }
        if (amount == 0) {
            revert InvalidAmount();
        }
        if (_paused) {
            revert Paused();
        }
        if (_blacklisted[to]) {
            revert BlacklistedAddress();
        }
        
        uint256 totalSupply = totalSupply();
        if (totalSupply + amount > _MAX_SUPPLY) {
            revert MaxSupplyExceeded();
        }
        
        _mint(to, amount);
        emit Mint(to, amount);
    }
    
    /**
     * @dev Burns tokens from caller's balance
     * @param amount The amount of tokens to burn
     * @notice Can only burn up to caller's balance
     */
    function burn(uint256 amount) external nonReentrant {
        if (amount == 0) {
            revert InvalidAmount();
        }
        if (_paused) {
            revert Paused();
        }
        
        _burn(msg.sender, amount);
        emit Burn(msg.sender, amount);
    }
    
    /**
     * @dev Burns tokens from a specific address
     * @param from The address to burn tokens from
     * @param amount The amount of tokens to burn
     * @notice Only approved spenders or owner can call this
     */
    function burnFrom(address from, uint256 amount) external nonReentrant {
        if (amount == 0) {
            revert InvalidAmount();
        }
        if (_paused) {
            revert Paused();
        }
        if (_blacklisted[from]) {
            revert BlacklistedAddress();
        }
        
        _burn(from, amount);
        emit Burn(from, amount);
    }
    
    /**
     * @dev Transfers tokens with additional safety checks
     * @param to The recipient address
     * @param amount The amount to transfer
     * @return bool indicating success
     */
    function transfer(address to, uint256 amount) public override returns (bool) {
        if (to == address(0)) {
            revert InvalidRecipient();
        }
        if (_paused) {
            revert Paused();
        }
        if (_blacklisted[msg.sender] || _blacklisted[to]) {
            revert BlacklistedAddress();
        }
        
        return super.transfer(to, amount);
    }
    
    /**
     * @dev Transfers tokens with additional safety checks
     * @param from The sender address
     * @param to The recipient address
     * @param amount The amount to transfer
     * @return bool indicating success
     */
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override returns (bool) {
        if (to == address(0)) {
            revert InvalidRecipient();
        }
        if (_paused) {
            revert Paused();
        }
        if (_blacklisted[from] || _blacklisted[to]) {
            revert BlacklistedAddress();
        }
        
        return super.transferFrom(from, to, amount);
    }
    
    /**
     * @dev Approves spending with additional safety checks
     * @param spender The address to approve
     * @param amount The amount to approve
     * @return bool indicating success
     */
    function approve(address spender, uint256 amount) public override returns (bool) {
        if (_paused) {
            revert Paused();
        }
        if (_blacklisted[spender]) {
            revert BlacklistedAddress();
        }
        
        return super.approve(spender, amount);
    }
    
    /**
     * @dev Sets approval with signature
     * @param owner The owner of tokens
     * @param spender The approved spender
     * @param amount The amount to approve
     * @param deadline The deadline for the signature
     * @param v The recovery byte of the signature
     * @param r Half of the ECDSA signature
     * @param s Half of the ECDSA signature
     * @return bool indicating success
     */
    function permit(
        address owner,
        address spender,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public override nonReentrant {
        if (_paused) {
            revert Paused();
        }
        if (_blacklisted[owner] || _blacklisted[spender]) {
            revert BlacklistedAddress();
        }
        
        super.permit(owner, spender, amount, deadline, v, r, s);
    }
    
    /**
     * @dev Pauses all token operations
     * @notice Only owner can call this function
     */
    function pause() external onlyOwner {
        if (_paused) {
            revert NotPaused();
        }
        _paused = true;
        emit Pause();
    }
    
    /**
     * @dev Unpauses all token operations
     * @notice Only owner can call this function
     */
    function unpause() external onlyOwner {
        if (!_paused) {
            revert Paused();
        }
        _paused = false;
        emit Unpause();
    }
    
    /**
     * @dev Adds an address to the blacklist
     * @param account The address to blacklist
     * @notice Only owner can call this function
     */
    function blacklist(address account) external onlyOwner {
        _blacklisted[account] = true;
    }
    
    /**
     * @dev Removes an address from the blacklist
     * @param account The address to remove from blacklist
     * @notice Only owner can call this function
     */
    function unblacklist(address account) external onlyOwner {
        _blacklisted[account] = false;
    }
    
    /**
     * @dev Checks if an address is blacklisted
     * @param account The address to check
     * @return bool indicating if address is blacklisted
     */
    function isBlacklisted(address account) external view returns (bool) {
        return _blacklisted[account];
    }
    
    /**
     * @dev Returns the paused status
     * @return bool indicating if token is paused
     */
    function isPaused() external view returns (bool) {
        return _paused;
    }
    
    /**
     * @dev Returns the maximum supply of tokens
     * @return uint256 representing max supply
     */
    function maxSupply() external pure returns (uint256) {
        return _MAX_SUPPLY;
    }
    
    /**
     * @dev Returns the token decimals
     * @return uint8 representing decimals
     */
    function decimals() public pure override returns (uint8) {
        return _DECIMALS;
    }
    
    /**
     * @dev Override to add pause check
     * @param account The account to check allowance for
     * @param spender The spender to check allowance for
     * @return uint256 representing allowance
     */
    function allowance(address account, address spender) public view override returns (uint256) {
        if (_paused) {
            return 0;
        }
        return super.allowance(account, spender);
    }
    
    /**
     * @dev Override to add pause check
     * @param account The account to check balance for
     * @return uint256 representing balance
     */
    function balanceOf(address account) public view override returns (uint256) {
        if (_paused) {
            return 0;
        }
        return super.balanceOf(account);
    }
}
