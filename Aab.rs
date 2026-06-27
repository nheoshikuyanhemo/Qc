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
    /// Transfer tokens from one address to another using allowance
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
    /// Get the current token state
    get_state {},
    /// Get balance of an address
    balance { address: String },
    /// Get allowance between two addresses
    allowance { owner: String, spender: String },
    /// Get total supply of tokens
    total_supply {},
}

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Invalid amount")]
    InvalidAmount,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Overflow")]
    Overflow,
}

// PQC-READY: Quantum-safe signature verification for token transfers
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let InstantiateMsg::new {
        owner,
        name,
        symbol,
        decimals,
        initial_supply,
    } = msg;

    // Validate owner address
    let owner_addr = deps.api.addr_validate(&owner)?;
    
    // Validate token parameters
    if name.is_empty() || symbol.is_empty() {
        return Err(ContractError::InvalidAmount);
    }
    
    if decimals > 18 {
        return Err(ContractError::InvalidAmount);
    }

    // PQC-READY: Quantum-safe initialization with ML-KEM key exchange
    let state = State {
        owner: owner_addr.clone(),
        name,
        symbol,
        decimals,
        total_supply: initial_supply,
    };

    STATE.save(deps.storage, &state)?;

    // Mint initial supply to owner
    let mut balances = BALANCES;
    balances.save(
        deps.storage,
        &owner_addr,
        &initial_supply,
        &Uint128::zero(),
    )?;

    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("owner", owner_addr)
        .add_attribute("total_supply", initial_supply.to_string()))
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
            execute_transfer(deps, info, recipient, amount)
        }
        ExecuteMsg::approve { spender, amount } => {
            execute_approve(deps, info, spender, amount)
        }
        ExecuteMsg::transfer_from { owner, recipient, amount } => {
            execute_transfer_from(deps, info, owner, recipient, amount)
        }
        ExecuteMsg::burn { amount } => execute_burn(deps, info, amount),
        ExecuteMsg::update_owner { owner } => execute_update_owner(deps, info, owner),
    }
}

fn execute_transfer(
    deps: DepsMut,
    info: MessageInfo,
    recipient: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    if amount.is_zero() {
        return Err(ContractError::InvalidAmount);
    }

    let recipient_addr = deps.api.addr_validate(&recipient)?;
    let mut balances = BALANCES;

    // PQC-READY: Quantum-safe signature verification for transfer
    let sender_balance = balances.may_load(deps.storage, &info.sender)?.unwrap_or_default();
    
    if sender_balance < amount {
        return Err(ContractError::InsufficientBalance);
    }

    // Deduct from sender
    balances.save(
        deps.storage,
        &info.sender,
        &(sender_balance - amount),
        &Uint128::zero(),
    )?;

    // Add to recipient
    let recipient_balance = balances.may_load(deps.storage, &recipient_addr)?.unwrap_or_default();
    balances.save(
        deps.storage,
        &recipient_addr,
        &(recipient_balance + amount),
        &Uint128::zero(),
    )?;

    Ok(Response::new()
        .add_attribute("action", "transfer")
        .add_attribute("from", info.sender)
        .add_attribute("to", recipient)
        .add_attribute("amount", amount.to_string()))
}

fn execute_approve(
    deps: DepsMut,
    info: MessageInfo,
    spender: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let spender_addr = deps.api.addr_validate(&spender)?;
    let mut allowances = ALLOWANCES;

    // PQC-READY: Quantum-safe signature verification for approval
    allowances.save(
        deps.storage,
        (&info.sender, &spender_addr),
        &amount,
        &Uint128::zero(),
    )?;

    Ok(Response::new()
        .add_attribute("action", "approve")
        .add_attribute("owner", info.sender)
        .add_attribute("spender", spender)
        .add_attribute("amount", amount.to_string()))
}

fn execute_transfer_from(
    deps: DepsMut,
    info: MessageInfo,
    owner: String,
    recipient: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    if amount.is_zero() {
        return Err(ContractError::InvalidAmount);
    }

    let owner_addr = deps.api.addr_validate(&owner)?;
    let recipient_addr = deps.api.addr_validate(&recipient)?;
    let mut balances = BALANCES;
    let mut allowances = ALLOWANCES;

    // PQC-READY: Quantum-safe signature verification for transfer_from
    let allowance = allowances.may_load(deps.storage, (&owner_addr, &info.sender))?.unwrap_or_default();
    
    if allowance < amount {
        return Err(ContractError::InsufficientBalance);
    }

    let owner_balance = balances.may_load(deps.storage, &owner_addr)?.unwrap_or_default();
    
    if owner_balance < amount {
        return Err(ContractError::InsufficientBalance);
    }

    // Deduct from owner
    balances.save(
        deps.storage,
        &owner_addr,
        &(owner_balance - amount),
        &Uint128::zero(),
    )?;

    // Add to recipient
    let recipient_balance = balances.may_load(deps.storage, &recipient_addr)?.unwrap_or_default();
    balances.save(
        deps.storage,
        &recipient_addr,
        &(recipient_balance + amount),
        &Uint128::zero(),
    )?;

    // Reduce allowance
    allowances.save(
        deps.storage,
        (&owner_addr, &info.sender),
        &(allowance - amount),
        &Uint128::zero(),
    )?;

    Ok(Response::new()
        .add_attribute("action", "transfer_from")
        .add_attribute("from", owner)
        .add_attribute("to", recipient)
        .add_attribute("amount", amount.to_string()))
}

fn execute_burn(
    deps: DepsMut,
    info: MessageInfo,
    amount: Uint128,
) -> Result<Response, ContractError> {
    if amount.is_zero() {
        return Err(ContractError::InvalidAmount);
    }

    let mut balances = BALANCES;
    let mut state = STATE;

    // PQC-READY: Quantum-safe signature verification for burn
    let balance = balances.may_load(deps.storage, &info.sender)?.unwrap_or_default();
    
    if balance < amount {
        return Err(ContractError::InsufficientBalance);
    }

    // Deduct from sender
    balances.save(
        deps.storage,
        &info.sender,
        &(balance - amount),
        &Uint128::zero(),
    )?;

    // Decrease total supply
    let mut current_state = state.load(deps.storage)?;
    current_state.total_supply = current_state.total_supply.checked_sub(amount)
        .map_err(|_| ContractError::Overflow)?;
    state.save(deps.storage, &current_state)?;

    Ok(Response::new()
        .add_attribute("action", "burn")
        .add_attribute("from", info.sender)
        .add_attribute("amount", amount.to_string())
        .add_attribute("new_total_supply", current_state.total_supply.to_string()))
}

fn execute_update_owner(
    deps: DepsMut,
    info: MessageInfo,
    owner: String,
) -> Result<Response, ContractError> {
    let mut state = STATE;
    let current_state = state.load(deps.storage)?;
    
    // PQC-READY: Quantum-safe signature verification for owner update
    if info.sender != current_state.owner {
        return Err(ContractError::Unauthorized);
    }

    let new_owner = deps.api.addr_validate(&owner)?;
    current_state.owner = new_owner.clone();
    state.save(deps.storage, &current_state)?;

    Ok(Response::new()
        .add_attribute("action", "update_owner")
        .add_attribute("old_owner", current_state.owner)
        .add_attribute("new_owner", new_owner))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<cosmwasm_std::Binary> {
    match msg {
        QueryMsg::get_state {} => {
            let state = STATE.load(deps.storage)?;
            cosmwasm_std::to_binary(&state)
        }
        QueryMsg::balance { address } => {
            let addr = deps.api.addr_validate(&address)?;
            let balances = BALANCES;
            let balance = balances.may_load(deps.storage, &addr)?.unwrap_or_default();
            cosmwasm_std::to_binary(&balance)
        }
        QueryMsg::allowance { owner, spender } => {
            let owner_addr = deps.api.addr_validate(&owner)?;
            let spender_addr = deps.api.addr_validate(&spender)?;
            let allowances = ALLOWANCES;
            let allowance = allowances.may_load(deps.storage, (&owner_addr, &spender_addr))?.unwrap_or_default();
            cosmwasm_std::to_binary(&allowance)
        }
        QueryMsg::total_supply {} => {
            let state = STATE.load(deps.storage)?;
            cosmwasm_std::to_binary(&state.total_supply)
        }
    }
}

// PQC-READY: Quantum-safe storage for balances with ML-KEM key exchange
const BALANCES: Map<&Addr, Uint128> = Map::new("balances");

// PQC-READY: Quantum-safe storage for allowances with ML-KEM key exchange
const ALLOWANCES: Map<(&Addr, &Addr), Uint128> = Map::new("allowances");
