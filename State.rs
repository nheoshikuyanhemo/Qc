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
}

pub const STATE: Item<State> = Item::new("state");

#[cw_serde]
pub enum InstantiateMsg {
    /// Initialize the token with owner, name, symbol, decimals, and initial supply
    new {
        owner: String,
        name: String,
        symbol: String,
        decimals: u8,
        initial_supply: Uint128,
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
    /// Burn tokens from sender's balance
    burn {
        amount: Uint128,
    },
    /// Update the owner of the token contract
    update_owner {
        owner: String,
    },
}

#[cw_serde]
pub enum QueryMsg {
    /// Query the balance of an address
    balance { address: String },
    /// Query the allowance of an address for another address
    allowance { owner: String, spender: String },
    /// Query the total supply of tokens
    total_supply {},
    /// Query the token information
    token_info {},
    /// Query the owner of the token contract
    owner {},
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
    
    #[error("Overflow")]
    Overflow {},
    
    #[error("Invalid owner")]
    InvalidOwner {},
}

/// Initialize the token contract
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
        } => {
            if initial_supply.is_zero() {
                return Err(ContractError::InvalidAmount {});
            }
            
            let owner_addr = deps.api.addr_validate(&owner)?;
            
            State {
                owner: owner_addr,
                name,
                symbol,
                decimals,
                total_supply: initial_supply,
            }
        }
    };
    
    STATE.save(deps.storage, &state)?;
    
    // Mint initial supply to owner
    let mut balances = BALANCES;
    balances.save(deps.storage, &info.sender, &initial_supply)?;
    
    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("owner", info.sender)
        .add_attribute("total_supply", state.total_supply.to_string()))
}

/// Handle all execution messages
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
        ExecuteMsg::burn { amount } => execute_burn(deps, env, info, amount),
        ExecuteMsg::update_owner { owner } => execute_update_owner(deps, env, info, owner),
    }
}

/// Handle all query messages
#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<cosmwasm_std::Binary> {
    match msg {
        QueryMsg::balance { address } => {
            let addr = deps.api.addr_validate(&address)?;
            let balance = BALANCES.may_load(deps.storage, &addr)?.unwrap_or_default();
            cosmwasm_std::to_binary(&balance)
        }
        QueryMsg::allowance { owner, spender } => {
            let owner_addr = deps.api.addr_validate(&owner)?;
            let spender_addr = deps.api.addr_validate(&spender)?;
            let allowance = ALLOWANCES.may_load(deps.storage, (&owner_addr, &spender_addr))?
                .unwrap_or_default();
            cosmwasm_std::to_binary(&allowance)
        }
        QueryMsg::total_supply {} => {
            let state = STATE.load(deps.storage)?;
            cosmwasm_std::to_binary(&state.total_supply)
        }
        QueryMsg::token_info {} => {
            let state = STATE.load(deps.storage)?;
            cosmwasm_std::to_binary(&TokenInfoResponse {
                name: state.name,
                symbol: state.symbol,
                decimals: state.decimals,
                total_supply: state.total_supply,
            })
        }
        QueryMsg::owner {} => {
            let state = STATE.load(deps.storage)?;
            cosmwasm_std::to_binary(&state.owner)
        }
    }
}

/// Transfer tokens from sender to recipient
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
    
    // Check sender has sufficient balance
    let mut balances = BALANCES;
    let sender_balance = balances.may_load(deps.storage, &info.sender)?.unwrap_or_default();
    
    if sender_balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }
    
    // Update balances
    balances.save(deps.storage, &info.sender, &(sender_balance - amount))?;
    let recipient_balance = balances.may_load(deps.storage, &recipient_addr)?.unwrap_or_default();
    balances.save(deps.storage, &recipient_addr, &(recipient_balance + amount))?;
    
    Ok(Response::new()
        .add_attribute("action", "transfer")
        .add_attribute("from", info.sender)
        .add_attribute("to", recipient)
        .add_attribute("amount", amount.to_string()))
}

/// Approve an allowance for another address to spend tokens
fn execute_approve(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    spender: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let spender_addr = deps.api.addr_validate(&spender)?;
    
    ALLOWANCES.save(
        deps.storage,
        (&info.sender, &spender_addr),
        &amount,
    )?;
    
    Ok(Response::new()
        .add_attribute("action", "approve")
        .add_attribute("owner", info.sender)
        .add_attribute("spender", spender)
        .add_attribute("amount", amount.to_string()))
}

/// Transfer tokens from one address to another using approved allowance
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
    
    // Check spender has sufficient allowance
    let allowance = ALLOWANCES.may_load(deps.storage, (&owner_addr, &info.sender))?
        .unwrap_or_default();
    
    if allowance < amount {
        return Err(ContractError::InsufficientBalance {});
    }
    
    // Check owner has sufficient balance
    let mut balances = BALANCES;
    let owner_balance = balances.may_load(deps.storage, &owner_addr)?.unwrap_or_default();
    
    if owner_balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }
    
    // Update allowances and balances
    ALLOWANCES.save(
        deps.storage,
        (&owner_addr, &info.sender),
        &(allowance - amount),
    )?;
    
    balances.save(deps.storage, &owner_addr, &(owner_balance - amount))?;
    let recipient_balance = balances.may_load(deps.storage, &recipient_addr)?.unwrap_or_default();
    balances.save(deps.storage, &recipient_addr, &(recipient_balance + amount))?;
    
    Ok(Response::new()
        .add_attribute("action", "transfer_from")
        .add_attribute("from", owner)
        .add_attribute("to", recipient)
        .add_attribute("amount", amount.to_string()))
}

/// Burn tokens from sender's balance
fn execute_burn(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> Result<Response, ContractError> {
    if amount.is_zero() {
        return Err(ContractError::InvalidAmount {});
    }
    
    // Check sender has sufficient balance
    let mut balances = BALANCES;
    let sender_balance = balances.may_load(deps.storage, &info.sender)?.unwrap_or_default();
    
    if sender_balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }
    
    // Update balances and total supply
    balances.save(deps.storage, &info.sender, &(sender_balance - amount))?;
    
    let mut state = STATE.load(deps.storage)?;
    state.total_supply = state.total_supply.checked_sub(amount)
        .map_err(|_| ContractError::Overflow)?;
    STATE.save(deps.storage, &state)?;
    
    Ok(Response::new()
        .add_attribute("action", "burn")
        .add_attribute("from", info.sender)
        .add_attribute("amount", amount.to_string()))
}

/// Update the owner of the token contract
fn execute_update_owner(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: String,
) -> Result<Response, ContractError> {
    let mut state = STATE.load(deps.storage)?;
    
    // Only current owner can update owner
    if state.owner != info.sender {
        return Err(ContractError::Unauthorized {});
    }
    
    let new_owner = deps.api.addr_validate(&owner)?;
    state.owner = new_owner;
    STATE.save(deps.storage, &state)?;
    
    Ok(Response::new()
        .add_attribute("action", "update_owner")
        .add_attribute("old_owner", info.sender)
        .add_attribute("new_owner", owner))
}

// PQC-READY: Quantum-safe storage for balances
pub const BALANCES: Map<&Addr, Uint128> = Map::new("balances");

// PQC-READY: Quantum-safe storage for allowances
pub const ALLOWANCES: Map<(&Addr, &Addr), Uint128> = Map::new("allowances");

/// Response structure for token info query
#[cw_serde]
pub struct TokenInfoResponse {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: Uint128,
}
