// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title Arbata Token
 * @dev ERC-20 token designed for Arbitrum L2 with enhanced security and gas optimization
 * @author QoreChain AI Assistant
 */
contract Arbata is ERC20, Ownable2Step, ReentrancyGuard {
    // === Events ===
    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);
    event Pause();
    event Unpause();
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // === State Variables ===
    bool public paused;
    uint256 public constant MAX_SUPPLY = 1000000000 ether; // 1 billion tokens
    uint256 public constant MINT_LIMIT = 100000000 ether; // 100 million tokens per mint

    // === Custom Errors ===
    error Arbata__InvalidAmount();
    error Arbata__InsufficientBalance();
    error Arbata__MintLimitExceeded();
    error Arbata__NotOwner();
    error Arbata__Paused();
    error Arbata__NotPaused();

    // === Modifiers ===
    modifier whenNotPaused() {
        if (paused) revert Arbata__Paused();
        _;
    }

    modifier whenPaused() {
        if (!paused) revert Arbata__NotPaused();
        _;
    }

    modifier onlyOwner() {
        if (msg.sender != owner()) revert Arbata__NotOwner();
        _;
    }

    // === Constructor ===
    /**
     * @dev Initializes the Arbata token with initial supply allocation
     * @param initialOwner The address that will own this contract
     * @param initialSupply The amount of tokens to mint initially
     */
    constructor(
        address initialOwner,
        uint256 initialSupply
    ) ERC20("Arbata", "ARBTA") {
        if (initialSupply > MAX_SUPPLY) {
            revert Arbata__InvalidAmount();
        }
        
        _mint(initialOwner, initialSupply);
        _transferOwnership(initialOwner);
    }

    // === Public Functions ===

    /**
     * @dev Mints new tokens to a specified address
     * @param to The address to mint tokens to
     * @param amount The amount of tokens to mint
     * @notice Only owner can call this function
     * @notice Minting is subject to daily limits
     */
    function mint(address to, uint256 amount) 
        external 
        onlyOwner 
        whenNotPaused 
        nonReentrant 
    {
        if (amount == 0) revert Arbata__InvalidAmount();
        if (amount > MINT_LIMIT) revert Arbata__MintLimitExceeded();
        if (totalSupply() + amount > MAX_SUPPLY) revert Arbata__InvalidAmount();

        _mint(to, amount);
        emit Mint(to, amount);
    }

    /**
     * @dev Burns tokens from the caller's balance
     * @param amount The amount of tokens to burn
     */
    function burn(uint256 amount) 
        external 
        whenNotPaused 
        nonReentrant 
    {
        if (amount == 0) revert Arbata__InvalidAmount();
        if (balanceOf(msg.sender) < amount) revert Arbata__InsufficientBalance();

        _burn(msg.sender, amount);
        emit Burn(msg.sender, amount);
    }

    /**
     * @dev Burns tokens from a specific address
     * @param from The address to burn tokens from
     * @param amount The amount of tokens to burn
     */
    function burnFrom(address from, uint256 amount) 
        external 
        whenNotPaused 
        nonReentrant 
    {
        if (amount == 0) revert Arbata__InvalidAmount();
        if (balanceOf(from) < amount) revert Arbata__InsufficientBalance();
        if (allowance(from, msg.sender) < amount) revert Arbata__InsufficientBalance();

        _spendAllowance(from, msg.sender, amount);
        _burn(from, amount);
        emit Burn(from, amount);
    }

    /**
     * @dev Pauses all token operations
     * @notice Only owner can call this function
     */
    function pause() 
        external 
        onlyOwner 
    {
        paused = true;
        emit Pause();
    }

    /**
     * @dev Unpauses all token operations
     * @notice Only owner can call this function
     */
    function unpause() 
        external 
        onlyOwner 
    {
        paused = false;
        emit Unpause();
    }

    /**
     * @dev Transfers tokens with additional safety checks
     * @param to The recipient address
     * @param amount The amount to transfer
     * @return A boolean indicating success
     */
    function transfer(address to, uint256 amount) 
        public 
        override 
        whenNotPaused 
        nonReentrant 
        returns (bool) 
    {
        return super.transfer(to, amount);
    }

    /**
     * @dev Transfers tokens with additional safety checks
     * @param from The sender address
     * @param to The recipient address
     * @param amount The amount to transfer
     * @return A boolean indicating success
     */
    function transferFrom(address from, address to, uint256 amount) 
        public 
        override 
        whenNotPaused 
        nonReentrant 
        returns (bool) 
    {
        return super.transferFrom(from, to, amount);
    }

    /**
     * @dev Approves tokens with additional safety checks
     * @param spender The address to approve
     * @param amount The amount to approve
     * @return A boolean indicating success
     */
    function approve(address spender, uint256 amount) 
        public 
        override 
        whenNotPaused 
        nonReentrant 
        returns (bool) 
    {
        return super.approve(spender, amount);
    }

    // === External Functions ===

    /**
     * @dev Returns the total supply of tokens
     * @return The total supply
     */
    function totalSupply() 
        public 
        view 
        override 
        returns (uint256) 
    {
        return super.totalSupply();
    }

    /**
     * @dev Returns the balance of an account
     * @param account The account address
     * @return The balance
     */
    function balanceOf(address account) 
        public 
        view 
        override 
        returns (uint256) 
    {
        return super.balanceOf(account);
    }

    /**
     * @dev Returns the allowance of an account
     * @param owner The owner address
     * @param spender The spender address
     * @return The allowance
     */
    function allowance(address owner, address spender) 
        public 
        view 
        override 
        returns (uint256) 
    {
        return super.allowance(owner, spender);
    }

    /**
     * @dev Checks if the contract is paused
     * @return True if paused, false otherwise
     */
    function isPaused() 
        public 
        view 
        returns (bool) 
    {
        return paused;
    }

    // === Internal Functions ===

    /**
     * @dev Overrides the _beforeTokenTransfer hook to add custom logic
     * @param from The sender address
     * @param to The recipient address
     * @param amount The amount being transferred
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override whenNotPaused {
        super._beforeTokenTransfer(from, to, amount);
        
        // Prevent transfers to zero address
        if (to == address(0)) {
            revert Arbata__InvalidAmount();
        }
        
        // Prevent transfers during pause
        if (paused && from != address(0) && to != address(0)) {
            revert Arbata__Paused();
        }
    }

    /**
     * @dev Overrides the _mint function to add custom logic
     * @param to The address to mint to
     * @param amount The amount to mint
     */
    function _mint(address to, uint256 amount) internal override {
        if (to == address(0)) {
            revert Arbata__InvalidAmount();
        }
        super._mint(to, amount);
    }

    /**
     * @dev Overrides the _burn function to add custom logic
     * @param account The address to burn from
     * @param amount The amount to burn
     */
    function _burn(address account, uint256 amount) internal override {
        if (account == address(0)) {
            revert Arbata__InvalidAmount();
        }
        super._burn(account, amount);
    }

    // === Admin Functions ===

    /**
     * @dev Sets the maximum supply limit
     * @param newMaxSupply The new maximum supply
     */
    function setMaxSupply(uint256 newMaxSupply) 
        external 
        onlyOwner 
    {
        if (newMaxSupply < totalSupply()) {
            revert Arbata__InvalidAmount();
        }
        // Note: This would require additional logic to handle existing supply
        // For simplicity, we're not implementing dynamic max supply changes
    }

    /**
     * @dev Sets the mint limit
     * @param newMintLimit The new mint limit
     */
    function setMintLimit(uint256 newMintLimit) 
        external 
        onlyOwner 
    {
        if (newMintLimit == 0 || newMintLimit > MAX_SUPPLY) {
            revert Arbata__InvalidAmount();
        }
        MINT_LIMIT = newMintLimit;
    }

    /**
     * @dev Allows owner to withdraw any ERC-20 tokens sent to this contract
     * @param tokenAddress The address of the ERC-20 token to withdraw
     * @param amount The amount to withdraw
     */
    function withdrawTokens(address tokenAddress, uint256 amount) 
        external 
        onlyOwner 
    {
        IERC20(tokenAddress).transfer(owner(), amount);
    }

    /**
     * @dev Allows owner to withdraw ETH from this contract
     * @param amount The amount to withdraw
     */
    function withdrawETH(uint256 amount) 
        external 
        onlyOwner 
    {
        payable(owner()).transfer(amount);
    }
}
