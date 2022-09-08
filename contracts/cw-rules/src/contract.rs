use cw_croncat_core::types::Rule;
// use schemars::JsonSchema;
// use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, has_coins, to_binary, to_vec, Binary, Deps, DepsMut, Empty, Env, MessageInfo,
    QueryRequest, Response, StdError, StdResult, WasmQuery,
};
use cw2::set_contract_version;
use cw20::{Balance, BalanceResponse};
use cw721::Cw721QueryMsg::OwnerOf;
use cw721::OwnerOfResponse;

use crate::error::ContractError;
use crate::helpers::{ValueOrd, ValueOrdering};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, RuleResponse};

//use cosmwasm_std::from_binary;
//use crate::msg::QueryMultiResponse;
use crate::types::dao::{ProposalResponse, QueryDao, Status};
use crate::types::generic_query::{GenericQuery, ValueIndex};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:cw-rules";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new().add_attribute("method", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        // Echo
        ExecuteMsg::QueryResult {} => query_result(deps, info),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetBalance { address, denom } => {
            to_binary(&query_get_balance(deps, address, denom)?)
        }
        QueryMsg::GetCW20Balance {
            cw20_contract,
            address,
        } => to_binary(&query_get_cw20_balance(deps, cw20_contract, address)?),
        QueryMsg::HasBalance {
            balance,
            required_balance,
        } => to_binary(&query_has_balance(balance, required_balance)?),
        QueryMsg::CheckOwnerOfNFT {
            address,
            nft_address,
            token_id,
        } => to_binary(&query_check_owner_nft(
            deps,
            address,
            nft_address,
            token_id,
        )?),
        QueryMsg::CheckProposalReadyToExec {
            dao_address,
            proposal_id,
            status,
        } => to_binary(&query_dao_proposal_status(
            deps,
            dao_address,
            proposal_id,
            status,
        )?),
        QueryMsg::QueryConstruct { rules } => to_binary(&query_construct(deps, rules)?),
    }
}

pub fn query_result(_deps: DepsMut, _info: MessageInfo) -> Result<Response, ContractError> {
    Ok(Response::new().add_attribute("method", "query_result"))
}

fn query_get_balance(
    deps: Deps,
    address: String,
    denom: String,
) -> StdResult<RuleResponse<Option<Binary>>> {
    let valid_addr = deps.api.addr_validate(&address)?;
    let amount = deps.querier.query_balance(valid_addr, denom)?.amount;
    if amount.is_zero() {
        Ok((true, None))
    } else {
        Ok((true, to_binary(&amount).ok()))
    }
}

fn query_get_cw20_balance(
    deps: Deps,
    cw20_contract: String,
    address: String,
) -> StdResult<RuleResponse<Option<Binary>>> {
    let valid_cw20 = deps.api.addr_validate(&cw20_contract)?;
    let balance: BalanceResponse = deps
        .querier
        .query_wasm_smart(valid_cw20, &cw20::Cw20QueryMsg::Balance { address })?;
    let amount = if balance.balance.is_zero() {
        None
    } else {
        Some(to_binary(&balance.balance)?)
    };
    Ok((true, amount))
}

fn query_has_balance(
    balance: Balance,
    required_balance: Balance,
) -> StdResult<RuleResponse<Option<Binary>>> {
    let res = match (balance, required_balance) {
        (Balance::Native(current), Balance::Native(expected)) => {
            expected.0.iter().all(|c| has_coins(&current.0, c))
        }
        (Balance::Cw20(current_cw20), Balance::Cw20(expected_cw20)) => {
            current_cw20.address == expected_cw20.address
                && current_cw20.amount >= expected_cw20.amount
        }
        _ => false,
    };
    Ok((res, None))
}

fn query_check_owner_nft(
    deps: Deps,
    address: String,
    nft_address: String,
    token_id: String,
) -> StdResult<RuleResponse<Option<Binary>>> {
    let valid_nft = deps.api.addr_validate(&nft_address)?;
    let res: OwnerOfResponse = deps.querier.query_wasm_smart(
        valid_nft,
        &OwnerOf {
            token_id,
            include_expired: None,
        },
    )?;
    Ok((address == res.owner, None))
}

fn query_dao_proposal_status(
    deps: Deps,
    dao_address: String,
    proposal_id: u64,
    status: Status,
) -> StdResult<RuleResponse<Option<Binary>>> {
    let dao_addr = deps.api.addr_validate(&dao_address)?;
    let res: ProposalResponse = deps
        .querier
        .query_wasm_smart(dao_addr, &QueryDao::Proposal { proposal_id })?;
    Ok((res.proposal.status == status, None))
}

// // // GOAL:
// // // Parse a generic query response, and inject input for the next query
// // fn query_chain(deps: Deps, env: Env) -> StdResult<QueryMultiResponse> {
// //     // Get known format for first msg
// //     let msg1 = QueryMsg::GetRandom {};
// //     let res1: RandomResponse = deps
// //         .querier
// //         .query_wasm_smart(&env.contract.address, &msg1)?;

//     // Query a bool with some data from previous
//     let msg2 = QueryMsg::GetBoolBinary {
//         msg: Some(to_binary(&res1)?),
//     };
//     let res2: RuleResponse<Option<Binary>> = deps
//         .querier
//         .query_wasm_smart(&env.contract.address, &msg2)?;

//     // Utilize previous query for the input of this query
//     // TODO: Setup binary msg, parse into something that contains { msg }, then assign the new binary response to it (if any)
//     // let msg = QueryMsg::GetInputBoolBinary {
//     //     msg: Some(to_binary(&res2)?),
//     // };
//     // let res: RuleResponse<Option<Binary>> =
//     //     deps.querier.query_wasm_smart(&env.contract.address, &msg)?;

//     // Format something to read results
//     let data = format!("{:?}", res2);
//     Ok(QueryMultiResponse { data })
// }

// create a smart query into binary
fn query_construct(deps: Deps, rules: Vec<Rule>) -> StdResult<bool> {
    for rule in rules {
        let contract_addr = deps.api.addr_validate(&rule.contract_addr)?.into_string();
        let query: GenericQuery = from_binary(&rule.msg)?;

        let request = QueryRequest::<Empty>::Wasm(WasmQuery::Smart {
            contract_addr,
            msg: query.msg,
        });

        // Copied from `QuerierWrapper::query`
        // because serde_json_wasm fails to deserialize slice into `serde_json::Value`
        let raw = to_vec(&request).map_err(|serialize_err| {
            StdError::generic_err(format!("Serializing QueryRequest: {}", serialize_err))
        })?;
        let bin = match deps.querier.raw_query(&raw) {
            cosmwasm_std::SystemResult::Ok(cosmwasm_std::ContractResult::Ok(value)) => value,
            cosmwasm_std::SystemResult::Ok(cosmwasm_std::ContractResult::Err(contract_err)) => {
                return Err(StdError::generic_err(format!(
                    "Querier contract error: {}",
                    contract_err
                )));
            }
            cosmwasm_std::SystemResult::Err(system_err) => {
                return Err(StdError::generic_err(format!(
                    "Querier system error: {}",
                    system_err
                )));
            }
        };
        let json_val: Value = serde_json::from_slice(bin.as_slice())
            .map_err(|e| StdError::parse_err(std::any::type_name::<Value>(), e))?;

        let mut current_val = &json_val;
        for get in query.gets {
            match get {
                ValueIndex::Key(s) => {
                    current_val = current_val
                        .get(s)
                        .ok_or_else(|| StdError::generic_err("Invalid key for value"))?
                }
                ValueIndex::Number(n) => {
                    current_val = current_val
                        .get(n as usize)
                        .ok_or_else(|| StdError::generic_err("Invalid index for value"))?
                }
            }
        }
        if !match query.ordering {
            ValueOrdering::UnitAbove => current_val.bt(&query.value)?,
            ValueOrdering::UnitAboveEqual => current_val.be(&query.value)?,
            ValueOrdering::UnitBelow => current_val.lt(&query.value)?,
            ValueOrdering::UnitBelowEqual => current_val.le(&query.value)?,
            ValueOrdering::Equal => current_val.eq(&query.value),
        } {
            return Ok(false);
        }
    }
    Ok(true)
}

// //     // Format something to read results
// //     let data = format!("{:?}", res2);
// //     Ok(QueryMultiResponse { data })
// // }

// // create a smart query into binary
// fn query_construct(_deps: Deps, _env: Env, _rules: Vec<Rule>) -> StdResult<QueryMultiResponse> {
//     let input_binary = to_binary(&RandomResponse { number: 1235 })?;

//     // create an injectable blank msg
//     let json_msg = json!({
//         "get_random": {
//             "msg": "",
//             "key": "value"
//         }
//     });
//     // blank msg to binary
//     let msg_binary = to_binary(&json_msg.to_string())?;

//     // try to parse binary
//     let msg_unbinary: String = from_binary(&msg_binary)?;
//     // let msg_parsed: Value = serde_json::from_str(msg_unbinary);
//     let msg_parse = serde_json::from_str(msg_unbinary.as_str());
//     let mut msg_parsed: String = "".to_string();

//     // Attempt to peel the onion, and fill with goodness
//     if let Ok(msg_parse) = msg_parse {
//         let parsed: Value = msg_parse;
//         // travel n1 child keys
//         if parsed.is_object() {
//             for (_key, value) in parsed.as_object().unwrap().iter() {
//                 for (k, _v) in value.as_object().unwrap().iter() {
//                     // check if this key has "msg"
//                     if k == "msg" {
//                         // then replace "msg" with "input_binary"
//                         // TODO:
//                         // parsed[key][k] = input_binary;
//                         msg_parsed = input_binary.to_string();
//                     }
//                 }
//             }
//         }
//     }

//     // Lastly, attempt to make the actual query!
//     // let res1 = deps
//     //     .querier
//     //     .query_wasm_smart(&env.contract.address, &msg1)?;

//     // Format something to read results
//     // let data = format!("{:?}", res1);
//     let data = format!("{:?} :: {:?}", msg_binary, msg_parsed);
//     Ok(QueryMultiResponse { data })
// }