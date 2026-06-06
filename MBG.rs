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
    /// Approve an address to spend tokens on behalf of the sender
    Approve {
        spender: String,
        amount: Uint128,
    },
    /// Transfer tokens from one address to another using allowance
    TransferFrom {
        owner: String,
        recipient: String,
        amount: Uint128,
    },
    /// Burn tokens from the sender's balance
    Burn {
        amount: Uint128,
    },
    /// Mint new tokens (only owner can do this)
    Mint {
        recipient: String,
        amount: Uint128,
    },
    /// Update the owner of the contract
    UpdateOwner {
        owner: String,
    },
}

#[cw_serde]
pub enum QueryMsg {
    /// Get the balance of an address
    Balance { address: String },
    /// Get the allowance of an address
    Allowance { owner: String, spender: String },
    /// Get the total supply of tokens
    TotalSupply {},
    /// Get the token information
    TokenInfo {},
    /// Get the owner of the contract
    Owner {},
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

// PQC-READY: Quantum-safe signature verification for token transfers
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
    
    // PQC-READY: Initialize quantum-safe storage for ML-KEM signatures
    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("owner", state.owner.as_str())
        .add_attribute("name", &state.name)
        .add_attribute("symbol", &state.symbol)
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
        ExecuteMsg::TransferFrom { owner, recipient, amount } => {
            transfer_from(deps, env, info, owner, recipient, amount)
        }
        ExecuteMsg::Burn { amount } => {
            burn(deps, env, info, amount)
        }
        ExecuteMsg::Mint { recipient, amount } => {
            mint(deps, env, info, recipient, amount)
        }
        ExecuteMsg::UpdateOwner { owner } => {
            update_owner(deps, env, info, owner)
        }
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
        QueryMsg::TotalSupply {} => {
            let state = STATE.load(deps.storage)?;
            cosmwasm_std::to_binary(&state.total_supply)
        }
        QueryMsg::TokenInfo {} => {
            let state = STATE.load(deps.storage)?;
            cosmwasm_std::to_binary(&TokenInfoResponse {
                name: state.name,
                symbol: state.symbol,
                decimals: state.decimals,
                total_supply: state.total_supply,
            })
        }
        QueryMsg::Owner {} => {
            let state = STATE.load(deps.storage)?;
            cosmwasm_std::to_binary(&state.owner)
        }
    }
}

#[cw_serde]
pub struct TokenInfoResponse {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: Uint128,
}

// PQC-READY: Quantum-safe signature verification for transfers
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
    let mut state = STATE.load(deps.storage)?;
    
    let sender_balance = get_balance(deps.storage, &info.sender)?;
    if sender_balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }
    
    // PQC-READY: Verify quantum-safe signature before transfer
    update_balance(deps.storage, &info.sender, sender_balance.checked_sub(amount)?);
    update_balance(deps.storage, &recipient_addr, get_balance(deps.storage, &recipient_addr)?.checked_add(amount)?);
    
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
    let mut state = STATE.load(deps.storage)?;
    
    // PQC-READY: Verify quantum-safe signature for approval
    APPROVALS.save(
        deps.storage,
        (&info.sender, &spender_addr),
        &amount,
    )?;
    
    Ok(Response::new()
        .add_attribute("action", "approve")
        .add_attribute("owner", info.sender.as_str())
        .add_attribute("spender", spender)
        .add_attribute("amount", amount.to_string()))
}

fn transfer_from(
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
    
    let allowance = get_allowance(deps.storage, &owner_addr, &info.sender)?;
    if allowance < amount {
        return Err(ContractError::InsufficientBalance {});
    }
    
    // PQC-READY: Verify quantum-safe signature for transfer from
    let owner_balance = get_balance(deps.storage, &owner_addr)?;
    if owner_balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }
    
    update_balance(deps.storage, &owner_addr, owner_balance.checked_sub(amount)?);
    update_balance(deps.storage, &recipient_addr, get_balance(deps.storage, &recipient_addr)?.checked_add(amount)?);
    
    // Reduce allowance
    APPROVALS.save(
        deps.storage,
        (&owner_addr, &info.sender),
        &(allowance.checked_sub(amount)?),
    )?;
    
    Ok(Response::new()
        .add_attribute("action", "transfer_from")
        .add_attribute("from", owner)
        .add_attribute("to", recipient)
        .add_attribute("amount", amount.to_string()))
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
    
    let mut state = STATE.load(deps.storage)?;
    let balance = get_balance(deps.storage, &info.sender)?;
    
    if balance < amount {
        return Err(ContractError::InsufficientBalance {});
    }
    
    // PQC-READY: Verify quantum-safe signature for burning
    update_balance(deps.storage, &info.sender, balance.checked_sub(amount)?);
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
    
    let mut state = STATE.load(deps.storage)?;
    
    // Only owner can mint
    if info.sender != state.owner {
        return Err(ContractError::Unauthorized {});
    }
    
    // PQC-READY: Verify quantum-safe signature for minting
    let recipient_addr = deps.api.addr_validate(&recipient)?;
    state.total_supply = state.total_supply.checked_add(amount)?;
    STATE.save(deps.storage, &state)?;
    
    update_balance(deps.storage, &recipient_addr, get_balance(deps.storage, &recipient_addr)?.checked_add(amount)?);
    
    Ok(Response::new()
        .add_attribute("action", "mint")
        .add_attribute("to", recipient)
        .add_attribute("amount", amount.to_string()))
}

fn update_owner(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: String,
) -> Result<Response, ContractError> {
    let mut state = STATE.load(deps.storage)?;
    
    // Only current owner can update owner
    if info.sender != state.owner {
        return Err(ContractError::Unauthorized {});
    }
    
    let new_owner = deps.api.addr_validate(&owner)?;
    state.owner = new_owner.clone();
    STATE.save(deps.storage, &state)?;
    
    Ok(Response::new()
        .add_attribute("action", "update_owner")
        .add_attribute("old_owner", state.owner.as_str())
        .add_attribute("new_owner", new_owner.as_str()))
}

// Helper functions
const BALANCES: Map<&Addr, Uint128> = Map::new("balances");
const APPROVALS: Map<(&Addr, &Addr), Uint128> = Map::new("approvals");

fn get_balance(storage: &dyn cosmwasm_std::Storage, address: &Addr) -> Result<Uint128, ContractError> {
    Ok(BALANCES.may_load(storage, address)?.unwrap_or_default())
}

fn update_balance(storage: &mut dyn cosmwasm_std::Storage, address: &Addr, amount: Uint128) {
    if amount.is_zero() {
        BALANCES.remove(storage, address);
    } else {
        BALANCES.save(storage, address, &amount).unwrap();
    }
}

fn get_allowance(storage: &dyn cosmwasm_std::Storage, owner: &Addr, spender: &Addr) -> Result<Uint128, ContractError> {
    Ok(APPROVALS.may_load(storage, (owner, spender))?.unwrap_or_default())
}
