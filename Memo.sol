// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title MemoToken
 * @dev BEP-20 compliant token with memo support
 * @notice This token represents the "Memo" meme with 1 billion supply
 */
contract MemoToken is ERC20, Ownable2Step, ReentrancyGuard {
    // Custom errors
    error InvalidAmount();
    error InsufficientBalance();
    error MintingPaused();
    error BurningPaused();
    error TransferPaused();
    error MintingExceedsCap();
    error InvalidRecipient();

    // Constants
    uint256 private constant MAX_SUPPLY = 1_000_000_000 * 10**18; // 1 Billion tokens
    uint256 private constant MINTING_CAP = 1_000_000_000 * 10**18; // 1 Billion tokens

    // State variables
    bool public mintingPaused;
    bool public burningPaused;
    bool public transfersPaused;
    uint256 public totalMinted;
    
    // Events
    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);
    event MintingPausedChanged(bool paused);
    event BurningPausedChanged(bool paused);
    event TransfersPausedChanged(bool paused);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the MemoToken contract
     * @param initialOwner The initial owner of the contract
     */
    constructor(address initialOwner) ERC20("Memo", "MEMO") {
        if (initialOwner == address(0)) {
            revert InvalidRecipient();
        }
        
        _transferOwnership(initialOwner);
        
        // Mint initial supply to owner
        _mint(initialOwner, MAX_SUPPLY);
        totalMinted = MAX_SUPPLY;
    }

    /**
     * @dev Mints new tokens
     * @param to The address to mint tokens to
     * @param amount The amount of tokens to mint
     */
    function mint(address to, uint256 amount) external onlyOwner nonReentrant {
        if (mintingPaused) {
            revert MintingPaused();
        }
        
        if (to == address(0)) {
            revert InvalidRecipient();
        }
        
        if (amount == 0) {
            revert InvalidAmount();
        }
        
        if (totalMinted + amount > MINTING_CAP) {
            revert MintingExceedsCap();
        }
        
        _mint(to, amount);
        totalMinted += amount;
        emit Mint(to, amount);
    }

    /**
     * @dev Burns tokens from the caller's balance
     * @param amount The amount of tokens to burn
     */
    function burn(uint256 amount) external nonReentrant {
        if (burningPaused) {
            revert BurningPaused();
        }
        
        if (amount == 0) {
            revert InvalidAmount();
        }
        
        _burn(msg.sender, amount);
        emit Burn(msg.sender, amount);
    }

    /**
     * @dev Burns tokens from a specific address
     * @param from The address to burn tokens from
     * @param amount The amount of tokens to burn
     */
    function burnFrom(address from, uint256 amount) external nonReentrant {
        if (burningPaused) {
            revert BurningPaused();
        }
        
        if (amount == 0) {
            revert InvalidAmount();
        }
        
        _burn(from, amount);
        emit Burn(from, amount);
    }

    /**
     * @dev Pauses or unpauses minting
     * @param paused The pause state
     */
    function setMintingPaused(bool paused) external onlyOwner {
        mintingPaused = paused;
        emit MintingPausedChanged(paused);
    }

    /**
     * @dev Pauses or unpauses burning
     * @param paused The pause state
     */
    function setBurningPaused(bool paused) external onlyOwner {
        burningPaused = paused;
        emit BurningPausedChanged(paused);
    }

    /**
     * @dev Pauses or unpauses transfers
     * @param paused The pause state
     */
    function setTransfersPaused(bool paused) external onlyOwner {
        transfersPaused = paused;
        emit TransfersPausedChanged(paused);
    }

    /**
     * @dev Overrides transfer to implement transfer pausing
     * @param from The address transferring tokens
     * @param to The address receiving tokens
     * @param amount The amount of tokens to transfer
     */
    function _transfer(address from, address to, uint256 amount) internal override {
        if (transfersPaused && from != owner()) {
            revert TransferPaused();
        }
        
        if (to == address(0)) {
            revert InvalidRecipient();
        }
        
        super._transfer(from, to, amount);
    }

    /**
     * @dev Overrides transferFrom to implement transfer pausing
     * @param from The address transferring tokens
     * @param to The address receiving tokens
     * @param amount The amount of tokens to transfer
     */
    function _transferFrom(address from, address to, uint256 amount) internal override {
        if (transfersPaused && from != owner()) {
            revert TransferPaused();
        }
        
        if (to == address(0)) {
            revert InvalidRecipient();
        }
        
        super._transferFrom(from, to, amount);
    }

    /**
     * @dev Returns the owner of the contract
     * @return The owner address
     */
    function getOwner() external view returns (address) {
        return owner();
    }

    /**
     * @dev Returns the maximum supply of the token
     * @return The maximum supply
     */
    function maxSupply() external pure returns (uint256) {
        return MAX_SUPPLY;
    }

    /**
     * @dev Returns the minting cap of the token
     * @return The minting cap
     */
    function mintingCap() external pure returns (uint256) {
        return MINTING_CAP;
    }

    /**
     * @dev Returns the total minted amount
     * @return The total minted amount
     */
    function getTotalMinted() external view returns (uint256) {
        return totalMinted;
    }

    /**
     * @dev Returns the paused states
     * @return mintingPaused, burningPaused, transfersPaused
     */
    function getPauseStates() external view returns (bool, bool, bool) {
        return (mintingPaused, burningPaused, transfersPaused);
    }

    /**
     * @dev Override to prevent transfers when paused
     */
    function transfer(address to, uint256 amount) public override(ERC20) returns (bool) {
        if (transfersPaused && msg.sender != owner()) {
            revert TransferPaused();
        }
        return super.transfer(to, amount);
    }

    /**
     * @dev Override to prevent transfers when paused
     */
    function transferFrom(address from, address to, uint256 amount) 
        public override(ERC20) returns (bool) {
        if (transfersPaused && from != owner()) {
            revert TransferPaused();
        }
        return super.transferFrom(from, to, amount);
    }

    /**
     * @dev Override to prevent approvals when paused
     */
    function approve(address spender, uint256 amount) public override(ERC20) returns (bool) {
        if (transfersPaused && msg.sender != owner()) {
            revert TransferPaused();
        }
        return super.approve(spender, amount);
    }

    /**
     * @dev Override to prevent spending when paused
     */
    function increaseAllowance(address spender, uint256 addedValue) 
        public override(ERC20) returns (bool) {
        if (transfersPaused && msg.sender != owner()) {
            revert TransferPaused();
        }
        return super.increaseAllowance(spender, addedValue);
    }

    /**
     * @dev Override to prevent spending when paused
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) 
        public override(ERC20) returns (bool) {
        if (transfersPaused && msg.sender != owner()) {
            revert TransferPaused();
        }
        return super.decreaseAllowance(spender, subtractedValue);
    }
}
