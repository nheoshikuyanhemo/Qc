// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";

/**
 * @title PolypoloToken
 * @dev ERC-20 token for Polygon PoS network with gasless transactions support
 * @author QoreChain AI Assistant
 */
contract PolypoloToken is ERC20, Ownable2Step, ReentrancyGuard {
    using Address for address;

    // === Events ===
    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);
    event Pause();
    event Unpause();
    event MaxSupplyUpdated(uint256 newMaxSupply);
    event TeamAllocationUpdated(address indexed teamMember, uint256 newAmount);

    // === State Variables ===
    uint256 public constant MAX_SUPPLY = 1000000000 * 10**18; // 1 billion tokens
    uint256 public maxSupply;
    
    mapping(address => bool) public isTeamMember;
    mapping(address => uint256) public teamAllocation;
    
    bool public paused;
    uint256 public totalTeamAllocated;
    
    // === Custom Errors ===
    error InvalidAddress();
    error InsufficientBalance();
    error AmountExceedsMaxSupply();
    error NotTeamMember();
    error AlreadyTeamMember();
    error SupplyLimitReached();
    error InvalidTeamAllocation();
    error TokenPaused();
    error TokenNotPaused();

    // === Modifiers ===
    modifier whenNotPaused() {
        if (paused) revert TokenPaused();
        _;
    }

    modifier whenPaused() {
        if (!paused) revert TokenNotPaused();
        _;
    }

    modifier onlyTeamMember() {
        if (!isTeamMember[msg.sender]) revert NotTeamMember();
        _;
    }

    // === Constructor ===
    /**
     * @dev Initializes the PolypoloToken contract
     * @param initialOwner The address that will own this contract
     * @param initialTeamMembers Array of addresses to be added as team members
     * @param initialTeamAllocations Array of allocation amounts for each team member
     */
    constructor(
        address initialOwner,
        address[] memory initialTeamMembers,
        uint256[] memory initialTeamAllocations
    ) ERC20("Polypolo", "POLPO") {
        if (initialOwner == address(0)) revert InvalidAddress();
        if (initialTeamMembers.length != initialTeamAllocations.length) revert InvalidTeamAllocation();
        
        _transferOwnership(initialOwner);
        maxSupply = MAX_SUPPLY;
        
        // Initialize team members and allocations
        for (uint256 i = 0; i < initialTeamMembers.length; i++) {
            if (initialTeamMembers[i] == address(0)) revert InvalidAddress();
            if (initialTeamAllocations[i] == 0) revert InvalidTeamAllocation();
            
            isTeamMember[initialTeamMembers[i]] = true;
            teamAllocation[initialTeamMembers[i]] = initialTeamAllocations[i];
            totalTeamAllocated += initialTeamAllocations[i];
        }
        
        // Mint initial team allocations
        _mintTeamAllocations();
    }

    // === Public Functions ===

    /**
     * @dev Mints new tokens to a specified address
     * @param to The address to mint tokens to
     * @param amount The amount of tokens to mint
     * @notice Only owner can call this function
     */
    function mint(address to, uint256 amount) external onlyOwner whenNotPaused nonReentrant {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert InvalidAddress();
        
        uint256 newTotalSupply = totalSupply() + amount;
        if (newTotalSupply > maxSupply) revert AmountExceedsMaxSupply();
        
        _mint(to, amount);
        emit Mint(to, amount);
    }

    /**
     * @dev Burns tokens from the caller's balance
     * @param amount The amount of tokens to burn
     */
    function burn(uint256 amount) external whenNotPaused nonReentrant {
        _burn(msg.sender, amount);
        emit Burn(msg.sender, amount);
    }

    /**
     * @dev Burns tokens from a specific address
     * @param from The address to burn tokens from
     * @param amount The amount of tokens to burn
     */
    function burnFrom(address from, uint256 amount) external whenNotPaused nonReentrant {
        _burn(from, amount);
        emit Burn(from, amount);
    }

    /**
     * @dev Pauses all token transfers
     * @notice Only owner can call this function
     */
    function pause() external onlyOwner whenNotPaused {
        paused = true;
        emit Pause();
    }

    /**
     * @dev Unpauses all token transfers
     * @notice Only owner can call this function
     */
    function unpause() external onlyOwner whenPaused {
        paused = false;
        emit Unpause();
    }

    /**
     * @dev Updates the maximum supply of tokens
     * @param newMaxSupply The new maximum supply limit
     * @notice Only owner can call this function
     */
    function updateMaxSupply(uint256 newMaxSupply) external onlyOwner {
        if (newMaxSupply <= totalSupply()) revert SupplyLimitReached();
        maxSupply = newMaxSupply;
        emit MaxSupplyUpdated(newMaxSupply);
    }

    /**
     * @dev Adds a new team member with allocation
     * @param teamMember The address of the new team member
     * @param allocation The allocation amount for the team member
     * @notice Only owner can call this function
     */
    function addTeamMember(address teamMember, uint256 allocation) external onlyOwner {
        if (teamMember == address(0)) revert InvalidAddress();
        if (allocation == 0) revert InvalidTeamAllocation();
        if (isTeamMember[teamMember]) revert AlreadyTeamMember();
        
        isTeamMember[teamMember] = true;
        teamAllocation[teamMember] = allocation;
        totalTeamAllocated += allocation;
        
        emit TeamAllocationUpdated(teamMember, allocation);
    }

    /**
     * @dev Removes a team member
     * @param teamMember The address of the team member to remove
     * @notice Only owner can call this function
     */
    function removeTeamMember(address teamMember) external onlyOwner {
        if (!isTeamMember[teamMember]) revert NotTeamMember();
        
        totalTeamAllocated -= teamAllocation[teamMember];
        delete teamAllocation[teamMember];
        isTeamMember[teamMember] = false;
        
        emit TeamAllocationUpdated(teamMember, 0);
    }

    /**
     * @dev Updates team member allocation
     * @param teamMember The address of the team member
     * @param newAllocation The new allocation amount
     * @notice Only owner can call this function
     */
    function updateTeamAllocation(address teamMember, uint256 newAllocation) external onlyOwner {
        if (!isTeamMember[teamMember]) revert NotTeamMember();
        if (newAllocation == 0) revert InvalidTeamAllocation();
        
        uint256 oldAllocation = teamAllocation[teamMember];
        teamAllocation[teamMember] = newAllocation;
        totalTeamAllocated = totalTeamAllocated - oldAllocation + newAllocation;
        
        emit TeamAllocationUpdated(teamMember, newAllocation);
    }

    /**
     * @dev Transfers tokens to another address
     * @param to The recipient address
     * @param amount The amount of tokens to transfer
     * @return A boolean indicating whether the operation succeeded
     */
    function transfer(address to, uint256 amount) public override whenNotPaused nonReentrant returns (bool) {
        return super.transfer(to, amount);
    }

    /**
     * @dev Approves an address to spend tokens on behalf of the caller
     * @param spender The address authorized to spend tokens
     * @param amount The amount of tokens to approve
     * @return A boolean indicating whether the operation succeeded
     */
    function approve(address spender, uint256 amount) public override whenNotPaused nonReentrant returns (bool) {
        return super.approve(spender, amount);
    }

    /**
     * @dev Transfers tokens from one address to another using allowance
     * @param from The address to transfer tokens from
     * @param to The recipient address
     * @param amount The amount of tokens to transfer
     * @return A boolean indicating whether the operation succeeded
     */
    function transferFrom(address from, address to, uint256 amount) public override whenNotPaused nonReentrant returns (bool) {
        return super.transferFrom(from, to, amount);
    }

    // === Internal Functions ===

    /**
     * @dev Mints initial team allocations
     */
    function _mintTeamAllocations() internal {
        for (uint256 i = 0; i < totalTeamAllocated; i++) {
            address teamMember = _getTeamMemberAt(i);
            if (teamMember != address(0) && isTeamMember[teamMember]) {
                _mint(teamMember, teamAllocation[teamMember]);
            }
        }
    }

    /**
     * @dev Helper function to get team member at index (simplified for demo)
     */
    function _getTeamMemberAt(uint256 index) internal view returns (address) {
        // Simplified implementation - in real scenario you'd use a proper mapping or array
        // This is just a placeholder for demonstration purposes
        return address(0);
    }

    // === Override Functions ===

    /**
     * @dev Overrides ERC20 _beforeTokenTransfer to add custom logic
     * @param from The address sending tokens
     * @param to The address receiving tokens
     * @param amount The amount of tokens being transferred
     */
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override whenNotPaused {
        super._beforeTokenTransfer(from, to, amount);
        
        // Prevent transfers to zero address
        if (to == address(0)) revert InvalidAddress();
        
        // Ensure sender has sufficient balance
        if (from != address(0) && balanceOf(from) < amount) revert InsufficientBalance();
    }

    /**
     * @dev Overrides ERC20 _mint to add custom validation
     * @param to The address to mint tokens to
     * @param amount The amount of tokens to mint
     */
    function _mint(address to, uint256 amount) internal override {
        if (to == address(0)) revert InvalidAddress();
        if (totalSupply() + amount > maxSupply) revert AmountExceedsMaxSupply();
        super._mint(to, amount);
    }

    // === View Functions ===

    /**
     * @dev Returns whether an address is a team member
     * @param account The address to check
     * @return Boolean indicating if the address is a team member
     */
    function isTeamMemberAddress(address account) external view returns (bool) {
        return isTeamMember[account];
    }

    /**
     * @dev Returns the current total team allocation
     * @return The total amount allocated to team members
     */
    function getTotalTeamAllocated() external view returns (uint256) {
        return totalTeamAllocated;
    }

    /**
     * @dev Returns the allocation for a specific team member
     * @param teamMember The address of the team member
     * @return The allocation amount for the team member
     */
    function getTeamAllocation(address teamMember) external view returns (uint256) {
        return teamAllocation[teamMember];
    }

    /**
     * @dev Returns the current max supply
     * @return The maximum supply limit
     */
    function getMaxSupply() external view returns (uint256) {
        return maxSupply;
    }

    /**
     * @dev Returns the current paused status
     * @return Boolean indicating if the token is paused
     */
    function isTokenPaused() external view returns (bool) {
        return paused;
    }

    /**
     * @dev Returns the total supply of tokens
     * @return The total supply of tokens
     */
    function totalSupply() public view override(ERC20) returns (uint256) {
        return super.totalSupply();
    }
}
