use cosmwasm_std::{
    Addr, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint128,
};
use cw_storage_plus::{Item, Map};
use thiserror::Error;
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct State {
    pub owner: Addr,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: Uint128,
    pub mint_enabled: bool,
}

pub const STATE: Item<State> = Item::new("state");

#[cw_serde]
pub enum InstantiateMsg {
    /// Initialize the token with owner, name, symbol, decimals, initial supply, and minting capability
    new {
        owner: String,
        name: String,
        symbol: String,
        decimals: u8,
        initial_supply: Uint128,
        mint_enabled: bool,
    },
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Transfer tokens from sender to recipient
    transfer {
        recipient: String,
        amount: Uint128,
    },
    /// Approve an allowance for another address to spend tokens
    approve {
        spender: String,
        amount: Uint128,
    },
    /// Transfer tokens from one address to another using approved allowance
    transfer_from {
        owner: String,
        recipient: String,
        amount: Uint128,
    },
    /// Mint new tokens (only owner can do this)
    mint {
        recipient: String,
        amount: Uint128,
    },
    /// Burn tokens from sender's balance
    burn {
        amount: Uint128,
    },
    /// Update the owner of the contract
    update_owner {
        new_owner: String,
    },
    /// Toggle minting capability
    toggle_mint {
        enabled: bool,
    },
}

#[cw_serde]
pub enum QueryMsg {
    /// Get the current state of the token
    get_state {},
    /// Get the balance of an address
    balance { address: String },
    /// Get the allowance of an address for another address
    allowance { owner: String, spender: String },
    /// Get the total supply of tokens
    total_supply {},
}

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),
    
    #[error("Unauthorized")]
    Unauthorized {},
    
    #[error("Insufficient balance")]
    InsufficientBalance {},
    
    #[error("Invalid amount")]
    InvalidAmount {},
    
    #[error("Invalid address")]
    InvalidAddress {},
    
    #[error("Insufficient allowance")]
    InsufficientAllowance {},
    
    #[error("Minting disabled")]
    MintingDisabled {},
    
    #[error("Invalid owner")]
    InvalidOwner {},
}

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let state = match msg {
        InstantiateMsg::new {
            owner,
            name,
            symbol,
            decimals,
            initial_supply,
            mint_enabled,
        } => {
            let owner_addr = deps.api.addr_validate(&owner)?;
            State {
                owner: owner_addr,
                name,
                symbol,
                decimals,
                total_supply: initial_supply,
                mint_enabled,
            }
        }
    };

    STATE.save(deps.storage, &state)?;
    
    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("owner", state.owner.to_string())
        .add_attribute("name", state.name)
        .add_attribute("symbol", state.symbol)
        .add_attribute("decimals", state.decimals.to_string())
        .add_attribute("total_supply", state.total_supply.to_string()))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::transfer { recipient, amount } => {
            execute_transfer(deps, env, info, recipient, amount)
        }
        ExecuteMsg::approve { spender, amount } => {
            execute_approve(deps, env, info, spender, amount)
        }
        ExecuteMsg::transfer_from { owner, recipient, amount } => {
            execute_transfer_from(deps, env, info, owner, recipient, amount)
        }
        ExecuteMsg::mint { recipient, amount } => {
            execute_mint(deps, env, info, recipient, amount)
        }
        ExecuteMsg::burn { amount } => execute_burn(deps, env, info, amount),
        ExecuteMsg::update_owner { new_owner } => {
            execute_update_owner(deps, env, info, new_owner)
        }
        ExecuteMsg::toggle_mint { enabled } => {
            execute_toggle_mint(deps, env, info, enabled)
        }
    }
}

fn execute_transfer(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    recipient: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    if amount.is_zero() {
        return Err(ContractError::InvalidAmount {});
    }

    let recipient_addr = deps.api.addr_validate(&recipient)?;
    let mut state = STATE.load(deps.storage)?;

    // Check if sender has sufficient balance
    let sender_balance = get_balance(deps.as_ref(), info.sender.clone())?;
    if sender_balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }

    // Update balances
    update_balance(deps.storage, info.sender, -amount)?;
    update_balance(deps.storage, recipient_addr, amount)?;

    Ok(Response::new()
        .add_attribute("action", "transfer")
        .add_attribute("from", info.sender.to_string())
        .add_attribute("to", recipient)
        .add_attribute("amount", amount.to_string()))
}

fn execute_approve(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    spender: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let spender_addr = deps.api.addr_validate(&spender)?;
    let mut state = STATE.load(deps.storage)?;

    // Store allowance
    let allowance_key = ("allowance", info.sender.as_bytes(), spender_addr.as_bytes());
    let allowance_map = Map::<(&[u8], &[u8]), Uint128>::new("allowance");
    allowance_map.save(deps.storage, allowance_key, &amount)?;

    Ok(Response::new()
        .add_attribute("action", "approve")
        .add_attribute("owner", info.sender.to_string())
        .add_attribute("spender", spender)
        .add_attribute("amount", amount.to_string()))
}

fn execute_transfer_from(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: String,
    recipient: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    if amount.is_zero() {
        return Err(ContractError::InvalidAmount {});
    }

    let owner_addr = deps.api.addr_validate(&owner)?;
    let recipient_addr = deps.api.addr_validate(&recipient)?;
    let mut state = STATE.load(deps.storage)?;

    // Check if spender has sufficient allowance
    let allowance_key = ("allowance", owner_addr.as_bytes(), info.sender.as_bytes());
    let allowance_map = Map::<(&[u8], &[u8]), Uint128>::new("allowance");
    let allowance = allowance_map.may_load(deps.storage, allowance_key)?
        .unwrap_or(Uint128::zero());

    if allowance < amount {
        return Err(ContractError::InsufficientAllowance {});
    }

    // Check if owner has sufficient balance
    let owner_balance = get_balance(deps.as_ref(), owner_addr.clone())?;
    if owner_balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }

    // Update balances
    update_balance(deps.storage, owner_addr, -amount)?;
    update_balance(deps.storage, recipient_addr, amount)?;

    // Reduce allowance
    allowance_map.save(deps.storage, allowance_key, &(allowance - amount))?;

    Ok(Response::new()
        .add_attribute("action", "transfer_from")
        .add_attribute("from", owner)
        .add_attribute("to", recipient)
        .add_attribute("amount", amount.to_string()))
}

fn execute_mint(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    recipient: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let mut state = STATE.load(deps.storage)?;
    
    // Only owner can mint
    if info.sender != state.owner {
        return Err(ContractError::Unauthorized {});
    }
    
    // Check if minting is enabled
    if !state.mint_enabled {
        return Err(ContractError::MintingDisabled {});
    }
    
    if amount.is_zero() {
        return Err(ContractError::InvalidAmount {});
    }

    let recipient_addr = deps.api.addr_validate(&recipient)?;
    
    // Update total supply
    state.total_supply = state.total_supply.checked_add(amount)
        .map_err(|_| StdError::generic_err("Overflow in total supply"))?;
    
    // Update recipient balance
    update_balance(deps.storage, recipient_addr, amount)?;
    
    STATE.save(deps.storage, &state)?;
    
    Ok(Response::new()
        .add_attribute("action", "mint")
        .add_attribute("recipient", recipient)
        .add_attribute("amount", amount.to_string())
        .add_attribute("total_supply", state.total_supply.to_string()))
}

fn execute_burn(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> Result<Response, ContractError> {
    if amount.is_zero() {
        return Err(ContractError::InvalidAmount {});
    }

    let mut state = STATE.load(deps.storage)?;
    
    // Check if sender has sufficient balance
    let sender_balance = get_balance(deps.as_ref(), info.sender.clone())?;
    if sender_balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }

    // Update balances
    update_balance(deps.storage, info.sender, -amount)?;
    
    // Update total supply
    state.total_supply = state.total_supply.checked_sub(amount)
        .map_err(|_| StdError::generic_err("Underflow in total supply"))?;
    
    STATE.save(deps.storage, &state)?;
    
    Ok(Response::new()
        .add_attribute("action", "burn")
        .add_attribute("from", info.sender.to_string())
        .add_attribute("amount", amount.to_string())
        .add_attribute("total_supply", state.total_supply.to_string()))
}

fn execute_update_owner(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    new_owner: String,
) -> Result<Response, ContractError> {
    let mut state = STATE.load(deps.storage)?;
    
    // Only current owner can update owner
    if info.sender != state.owner {
        return Err(ContractError::Unauthorized {});
    }
    
    let new_owner_addr = deps.api.addr_validate(&new_owner)?;
    
    // Update owner
    state.owner = new_owner_addr;
    STATE.save(deps.storage, &state)?;
    
    Ok(Response::new()
        .add_attribute("action", "update_owner")
        .add_attribute("old_owner", info.sender.to_string())
        .add_attribute("new_owner", new_owner))
}

fn execute_toggle_mint(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    enabled: bool,
) -> Result<Response, ContractError> {
    let mut state = STATE.load(deps.storage)?;
    
    // Only owner can toggle minting
    if info.sender != state.owner {
        return Err(ContractError::Unauthorized {});
    }
    
    state.mint_enabled = enabled;
    STATE.save(deps.storage, &state)?;
    
    Ok(Response::new()
        .add_attribute("action", "toggle_mint")
        .add_attribute("enabled", enabled.to_string()))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<cosmwasm_std::Binary> {
    match msg {
        QueryMsg::get_state {} => {
            let state = STATE.load(deps.storage)?;
            Ok(cosmwasm_std::to_binary(&state)?)
        }
        QueryMsg::balance { address } => {
            let addr = deps.api.addr_validate(&address)?;
            let balance = get_balance(deps, addr)?;
            Ok(cosmwasm_std::to_binary(&balance)?)
        }
        QueryMsg::allowance { owner, spender } => {
            let owner_addr = deps.api.addr_validate(&owner)?;
            let spender_addr = deps.api.addr_validate(&spender)?;
            
            let allowance_key = ("allowance", owner_addr.as_bytes(), spender_addr.as_bytes());
            let allowance_map = Map::<(&[u8], &[u8]), Uint128>::new("allowance");
            let allowance = allowance_map.may_load(deps.storage, allowance_key)?
                .unwrap_or(Uint128::zero());
                
            Ok(cosmwasm_std::to_binary(&allowance)?)
        }
        QueryMsg::total_supply {} => {
            let state = STATE.load(deps.storage)?;
            Ok(cosmwasm_std::to_binary(&state.total_supply)?)
        }
    }
}

// Helper function to get balance
fn get_balance(deps: Deps, address: Addr) -> StdResult<Uint128> {
    let balance_key = ("balance", address.as_bytes());
    let balance_map = Map::<&[u8], Uint128>::new("balance");
    Ok(balance_map.may_load(deps.storage, balance_key)?.unwrap_or(Uint128::zero()))
}

// Helper function to update balance
fn update_balance(storage: &mut dyn cosmwasm_std::Storage, address: Addr, amount: Uint128) -> StdResult<()> {
    let balance_key = ("balance", address.as_bytes());
    let balance_map = Map::<&[u8], Uint128>::new("balance");
    
    let current_balance = balance_map.may_load(storage, balance_key)?.unwrap_or(Uint128::zero());
    let new_balance = current_balance.checked_add(amount)
        .map_err(|_| StdError::generic_err("Overflow in balance"))?;
    
    balance_map.save(storage, balance_key, &new_balance)?;
    Ok(())
}
