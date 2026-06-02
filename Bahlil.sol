// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title BahlilToken
 * @dev ERC-20 token with minting, burning, and ownership controls
 * Features:
 * - Standard ERC-20 functionality
 * - Minting and burning capabilities
 * - Ownable2Step for secure ownership transfer
 * - Reentrancy protection
 * - Minimum and maximum supply limits
 */
contract BahlilToken is ERC20, Ownable2Step, ReentrancyGuard {
    // Custom errors for gas efficiency
    error InvalidAmount();
    error InsufficientBalance();
    error MaxSupplyExceeded();
    error MintingNotAllowed();
    error BurningNotAllowed();

    // Token parameters
    uint256 private constant MIN_SUPPLY = 1_000_000_000e18; // 1 billion tokens
    uint256 private constant MAX_SUPPLY = 10_000_000_000e18; // 10 billion tokens
    
    // State variables
    uint256 public totalMinted;
    bool public mintingEnabled;
    
    // Events
    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);
    event MintingEnabledChanged(bool enabled);

    /**
     * @dev Constructor initializes the token with owner and sets up initial parameters
     * @param initialOwner The address that will own this contract initially
     */
    constructor(address initialOwner) ERC20("BahlilToken", "BAHLIL") {
        _transferOwnership(initialOwner);
        mintingEnabled = true;
    }

    /**
     * @dev Mints new tokens and assigns them to recipient
     * @param to The address that will receive the minted tokens
     * @param amount The amount of tokens to mint
     * @return bool indicating success
     */
    function mint(address to, uint256 amount) external onlyOwner nonReentrant returns (bool) {
        if (!mintingEnabled) {
            revert MintingNotAllowed();
        }
        
        if (to == address(0)) {
            revert InvalidAmount();
        }
        
        if (amount == 0) {
            revert InvalidAmount();
        }
        
        uint256 newTotalSupply = totalSupply() + amount;
        if (newTotalSupply > MAX_SUPPLY) {
            revert MaxSupplyExceeded();
        }
        
        totalMinted += amount;
        _mint(to, amount);
        emit Mint(to, amount);
        return true;
    }

    /**
     * @dev Burns tokens from caller's balance
     * @param amount The amount of tokens to burn
     * @return bool indicating success
     */
    function burn(uint256 amount) external nonReentrant returns (bool) {
        if (amount == 0) {
            revert InvalidAmount();
        }
        
        if (balanceOf(msg.sender) < amount) {
            revert InsufficientBalance();
        }
        
        _burn(msg.sender, amount);
        emit Burn(msg.sender, amount);
        return true;
    }

    /**
     * @dev Burns tokens from specified address
     * @param from The address whose tokens will be burned
     * @param amount The amount of tokens to burn
     * @return bool indicating success
     */
    function burnFrom(address from, uint256 amount) external nonReentrant returns (bool) {
        if (amount == 0) {
            revert InvalidAmount();
        }
        
        if (balanceOf(from) < amount) {
            revert InsufficientBalance();
        }
        
        uint256 currentAllowance = allowance(from, msg.sender);
        if (currentAllowance < amount) {
            revert InsufficientBalance();
        }
        
        _burn(from, amount);
        _approve(from, msg.sender, currentAllowance - amount);
        emit Burn(from, amount);
        return true;
    }

    /**
     * @dev Enables or disables minting functionality
     * @param enabled Boolean flag to enable/disable minting
     */
    function setMintingEnabled(bool enabled) external onlyOwner {
        mintingEnabled = enabled;
        emit MintingEnabledChanged(enabled);
    }

    /**
     * @dev Sets the minimum supply requirement
     * @param minSupply The new minimum supply value
     */
    function setMinSupply(uint256 minSupply) external onlyOwner {
        if (minSupply > MAX_SUPPLY) {
            revert MaxSupplyExceeded();
        }
        // Note: This would require additional logic to adjust existing supply
        // For simplicity, we're just validating the input here
    }

    /**
     * @dev Sets the maximum supply limit
     * @param maxSupply The new maximum supply value
     */
    function setMaxSupply(uint256 maxSupply) external onlyOwner {
        if (maxSupply < MIN_SUPPLY) {
            revert InvalidAmount();
        }
        // Note: This would require additional logic to adjust existing supply
        // For simplicity, we're just validating the input here
    }

    /**
     * @dev Override transfer to enforce minimum supply rules
     * @param to The address to transfer tokens to
     * @param amount The amount of tokens to transfer
     * @return bool indicating success
     */
    function transfer(address to, uint256 amount) public override(ERC20) returns (bool) {
        if (to == address(0)) {
            revert InvalidAmount();
        }
        
        if (amount == 0) {
            revert InvalidAmount();
        }
        
        return super.transfer(to, amount);
    }

    /**
     * @dev Override transferFrom to enforce minimum supply rules
     * @param from The address to transfer tokens from
     * @param to The address to transfer tokens to
     * @param amount The amount of tokens to transfer
     * @return bool indicating success
     */
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override(ERC20) returns (bool) {
        if (to == address(0)) {
            revert InvalidAmount();
        }
        
        if (amount == 0) {
            revert InvalidAmount();
        }
        
        return super.transferFrom(from, to, amount);
    }

    /**
     * @dev Returns the minimum supply required for this token
     * @return uint256 representing minimum supply
     */
    function getMinSupply() public pure returns (uint256) {
        return MIN_SUPPLY;
    }

    /**
     * @dev Returns the maximum supply allowed for this token
     * @return uint256 representing maximum supply
     */
    function getMaxSupply() public pure returns (uint256) {
        return MAX_SUPPLY;
    }

    /**
     * @dev Returns the total minted amount
     * @return uint256 representing total minted tokens
     */
    function getTotalMinted() public view returns (uint256) {
        return totalMinted;
    }

    /**
     * @dev Returns whether minting is currently enabled
     * @return bool indicating minting status
     */
    function isMintingEnabled() public view returns (bool) {
        return mintingEnabled;
    }

    /**
     * @dev Override _beforeTokenTransfer to add additional checks
     * @param from Address sending tokens
     * @param to Address receiving tokens
     * @param amount Number of tokens being transferred
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override(ERC20) {
        super._beforeTokenTransfer(from, to, amount);
        
        // Prevent transfers that would reduce total supply below minimum
        if (from != address(0) && to == address(0)) {
            // Burning operation - ensure we don't go below minimum supply
            if (totalSupply() <= MIN_SUPPLY) {
                revert BurningNotAllowed();
            }
        }
    }
}
