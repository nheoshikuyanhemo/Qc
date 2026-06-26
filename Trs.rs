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
    /// Initialize a new PQC Token with specified parameters
    Init {
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
    Transfer {
        recipient: String,
        amount: Uint128,
    },
    /// Approve an allowance for another address to spend tokens
    Approve {
        spender: String,
        amount: Uint128,
    },
    /// Decrease approved allowance
    DecreaseAllowance {
        spender: String,
        amount: Uint128,
    },
    /// Increase approved allowance
    IncreaseAllowance {
        spender: String,
        amount: Uint128,
    },
    /// Send tokens to another contract
    Send {
        recipient: String,
        amount: Uint128,
        msg: Option<String>,
    },
    /// Burn tokens from sender's balance
    Burn {
        amount: Uint128,
    },
    /// Mint new tokens (only owner can do this)
    Mint {
        recipient: String,
        amount: Uint128,
    },
    /// Update token ownership
    UpdateOwner {
        new_owner: String,
    },
}

#[cw_serde]
pub enum QueryMsg {
    /// Get token balance for an address
    Balance { address: String },
    /// Get token allowance for an address
    Allowance { owner: String, spender: String },
    /// Get token information
    TokenInfo {},
    /// Get token owner
    Owner {},
}

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),
    #[error("Unauthorized")]
    Unauthorized {},
    #[error("Insufficient Balance")]
    InsufficientBalance {},
    #[error("Invalid Amount")]
    InvalidAmount {},
    #[error("Invalid Address")]
    InvalidAddress {},
    #[error("Invalid Token Info")]
    InvalidTokenInfo {},
    #[error("Invalid Owner")]
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
        InstantiateMsg::Init {
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
    
    // PQC-READY: Initialize quantum-safe ML-KEM signature verification system
    // This would typically involve setting up quantum-resistant cryptographic primitives
    
    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("owner", state.owner.as_str())
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
        ExecuteMsg::Transfer { recipient, amount } => {
            transfer(deps, env, info, recipient, amount)
        }
        ExecuteMsg::Approve { spender, amount } => {
            approve(deps, env, info, spender, amount)
        }
        ExecuteMsg::DecreaseAllowance { spender, amount } => {
            decrease_allowance(deps, env, info, spender, amount)
        }
        ExecuteMsg::IncreaseAllowance { spender, amount } => {
            increase_allowance(deps, env, info, spender, amount)
        }
        ExecuteMsg::Send {
            recipient,
            amount,
            msg: send_msg,
        } => send(deps, env, info, recipient, amount, send_msg),
        ExecuteMsg::Burn { amount } => burn(deps, env, info, amount),
        ExecuteMsg::Mint { recipient, amount } => mint(deps, env, info, recipient, amount),
        ExecuteMsg::UpdateOwner { new_owner } => update_owner(deps, env, info, new_owner),
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<cosmwasm_std::Binary> {
    match msg {
        QueryMsg::Balance { address } => {
            let addr = deps.api.addr_validate(&address)?;
            let balance = get_balance(deps.storage, &addr)?;
            cosmwasm_std::to_binary(&balance)
        }
        QueryMsg::Allowance { owner, spender } => {
            let owner_addr = deps.api.addr_validate(&owner)?;
            let spender_addr = deps.api.addr_validate(&spender)?;
            let allowance = get_allowance(deps.storage, &owner_addr, &spender_addr)?;
            cosmwasm_std::to_binary(&allowance)
        }
        QueryMsg::TokenInfo {} => {
            let state = STATE.load(deps.storage)?;
            cosmwasm_std::to_binary(&state)
        }
        QueryMsg::Owner {} => {
            let state = STATE.load(deps.storage)?;
            cosmwasm_std::to_binary(&state.owner)
        }
    }
}

fn transfer(
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
    
    // PQC-READY: Verify quantum-safe signature for transfer operation
    // This would validate ML-KEM signatures for the transaction
    
    let mut state = STATE.load(deps.storage)?;
    
    let sender_balance = get_balance(deps.storage, &info.sender)?;
    if sender_balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }
    
    // Update balances
    set_balance(deps.storage, &info.sender, sender_balance.checked_sub(amount)?);
    let recipient_balance = get_balance(deps.storage, &recipient_addr)?;
    set_balance(deps.storage, &recipient_addr, recipient_balance.checked_add(amount)?);
    
    Ok(Response::new()
        .add_attribute("action", "transfer")
        .add_attribute("from", info.sender.as_str())
        .add_attribute("to", recipient)
        .add_attribute("amount", amount.to_string()))
}

fn approve(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    spender: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let spender_addr = deps.api.addr_validate(&spender)?;
    
    // PQC-READY: Verify quantum-safe signature for approval operation
    // This would validate ML-KEM signatures for the approval transaction
    
    let mut state = STATE.load(deps.storage)?;
    if info.sender == spender_addr {
        return Err(ContractError::InvalidAddress {});
    }
    
    set_allowance(deps.storage, &info.sender, &spender_addr, amount);
    
    Ok(Response::new()
        .add_attribute("action", "approve")
        .add_attribute("owner", info.sender.as_str())
        .add_attribute("spender", spender)
        .add_attribute("amount", amount.to_string()))
}

fn decrease_allowance(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    spender: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let spender_addr = deps.api.addr_validate(&spender)?;
    
    // PQC-READY: Verify quantum-safe signature for decrease allowance operation
    // This would validate ML-KEM signatures for the transaction
    
    let current_allowance = get_allowance(deps.storage, &info.sender, &spender_addr)?;
    let new_allowance = current_allowance.checked_sub(amount)?;
    
    set_allowance(deps.storage, &info.sender, &spender_addr, new_allowance);
    
    Ok(Response::new()
        .add_attribute("action", "decrease_allowance")
        .add_attribute("owner", info.sender.as_str())
        .add_attribute("spender", spender)
        .add_attribute("amount", amount.to_string()))
}

fn increase_allowance(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    spender: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let spender_addr = deps.api.addr_validate(&spender)?;
    
    // PQC-READY: Verify quantum-safe signature for increase allowance operation
    // This would validate ML-KEM signatures for the transaction
    
    let current_allowance = get_allowance(deps.storage, &info.sender, &spender_addr)?;
    let new_allowance = current_allowance.checked_add(amount)?;
    
    set_allowance(deps.storage, &info.sender, &spender_addr, new_allowance);
    
    Ok(Response::new()
        .add_attribute("action", "increase_allowance")
        .add_attribute("owner", info.sender.as_str())
        .add_attribute("spender", spender)
        .add_attribute("amount", amount.to_string()))
}

fn send(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    recipient: String,
    amount: Uint128,
    msg: Option<String>,
) -> Result<Response, ContractError> {
    if amount.is_zero() {
        return Err(ContractError::InvalidAmount {});
    }
    
    let recipient_addr = deps.api.addr_validate(&recipient)?;
    
    // PQC-READY: Verify quantum-safe signature for send operation
    // This would validate ML-KEM signatures for the transaction
    
    let mut state = STATE.load(deps.storage)?;
    let sender_balance = get_balance(deps.storage, &info.sender)?;
    if sender_balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }
    
    // Update balances
    set_balance(deps.storage, &info.sender, sender_balance.checked_sub(amount)?);
    let recipient_balance = get_balance(deps.storage, &recipient_addr)?;
    set_balance(deps.storage, &recipient_addr, recipient_balance.checked_add(amount)?);
    
    let mut response = Response::new()
        .add_attribute("action", "send")
        .add_attribute("from", info.sender.as_str())
        .add_attribute("to", recipient)
        .add_attribute("amount", amount.to_string());
    
    if let Some(send_msg) = msg {
        response = response.add_attribute("msg", send_msg);
    }
    
    Ok(response)
}

fn burn(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> Result<Response, ContractError> {
    if amount.is_zero() {
        return Err(ContractError::InvalidAmount {});
    }
    
    // PQC-READY: Verify quantum-safe signature for burn operation
    // This would validate ML-KEM signatures for the transaction
    
    let mut state = STATE.load(deps.storage)?;
    let sender_balance = get_balance(deps.storage, &info.sender)?;
    if sender_balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }
    
    // Update balances
    set_balance(deps.storage, &info.sender, sender_balance.checked_sub(amount)?);
    state.total_supply = state.total_supply.checked_sub(amount)?;
    STATE.save(deps.storage, &state)?;
    
    Ok(Response::new()
        .add_attribute("action", "burn")
        .add_attribute("from", info.sender.as_str())
        .add_attribute("amount", amount.to_string()))
}

fn mint(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    recipient: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    if amount.is_zero() {
        return Err(ContractError::InvalidAmount {});
    }
    
    // PQC-READY: Verify quantum-safe signature for mint operation
    // This would validate ML-KEM signatures for the transaction
    
    let mut state = STATE.load(deps.storage)?;
    if info.sender != state.owner {
        return Err(ContractError::Unauthorized {});
    }
    
    let recipient_addr = deps.api.addr_validate(&recipient)?;
    
    // Update balances
    let recipient_balance = get_balance(deps.storage, &recipient_addr)?;
    set_balance(deps.storage, &recipient_addr, recipient_balance.checked_add(amount)?);
    state.total_supply = state.total_supply.checked_add(amount)?;
    STATE.save(deps.storage, &state)?;
    
    Ok(Response::new()
        .add_attribute("action", "mint")
        .add_attribute("to", recipient)
        .add_attribute("amount", amount.to_string()))
}

fn update_owner(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    new_owner: String,
) -> Result<Response, ContractError> {
    let mut state = STATE.load(deps.storage)?;
    
    if info.sender != state.owner {
        return Err(ContractError::Unauthorized {});
    }
    
    let new_owner_addr = deps.api.addr_validate(&new_owner)?;
    state.owner = new_owner_addr;
    STATE.save(deps.storage, &state)?;
    
    Ok(Response::new()
        .add_attribute("action", "update_owner")
        .add_attribute("old_owner", info.sender.as_str())
        .add_attribute("new_owner", new_owner))
}

// Helper functions for storage management

const BALANCES: Map<&Addr, Uint128> = Map::new("balances");
const ALLOWANCES: Map<(&Addr, &Addr), Uint128> = Map::new("allowances");

fn get_balance(storage: &dyn cosmwasm_std::Storage, address: &Addr) -> StdResult<Uint128> {
    BALANCES.may_load(storage, address).map(|opt| opt.unwrap_or_default())
}

fn set_balance(storage: &mut dyn cosmwasm_std::Storage, address: &Addr, amount: Uint128) {
    if amount.is_zero() {
        BALANCES.remove(storage, address);
    } else {
        BALANCES.save(storage, address, &amount).unwrap();
    }
}

fn get_allowance(storage: &dyn cosmwasm_std::Storage, owner: &Addr, spender: &Addr) -> StdResult<Uint128> {
    ALLOWANCES.may_load(storage, (owner, spender)).map(|opt| opt.unwrap_or_default())
}

fn set_allowance(storage: &mut dyn cosmwasm_std::Storage, owner: &Addr, spender: &Addr, amount: Uint128) {
    if amount.is_zero() {
        ALLOWANCES.remove(storage, (owner, spender));
    } else {
        ALLOWANCES.save(storage, (owner, spender), &amount).unwrap();
    }
}
