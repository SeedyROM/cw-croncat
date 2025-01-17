use crate::balancer::Balancer;
use crate::error::ContractError;
use crate::helpers::{send_tokens, GenericBalance};
use crate::state::{Config, CwCroncat};
use cosmwasm_std::{
    has_coins, Addr, Coin, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Storage,
    SubMsg,
};
use cw_storage_plus::Bound;
use std::ops::Div;

use crate::ContractError::AgentNotRegistered;
use cw_croncat_core::msg::{AgentTaskResponse, GetAgentIdsResponse};
use cw_croncat_core::types::{calculate_required_amount, Agent, AgentResponse, AgentStatus};

impl<'a> CwCroncat<'a> {
    /// Get a single agent details
    /// Check's status as well, in case this agent needs to be considered for election
    pub(crate) fn query_get_agent(
        &self,
        deps: Deps,
        env: Env,
        account_id: String,
    ) -> StdResult<Option<AgentResponse>> {
        let account_id = deps.api.addr_validate(&account_id)?;
        let agent = self.agents.may_load(deps.storage, &account_id)?;
        if agent.is_none() {
            return Ok(None);
        }
        let active: Vec<Addr> = self.agent_active_queue.load(deps.storage)?;
        let a = agent.unwrap();
        let mut agent_response = AgentResponse {
            status: AgentStatus::Pending, // Simple default
            payable_account_id: a.payable_account_id,
            balance: a.balance,
            total_tasks_executed: a.total_tasks_executed,
            last_executed_slot: a.last_executed_slot,
            register_start: a.register_start,
        };

        if active.contains(&account_id) {
            agent_response.status = AgentStatus::Active;
            return Ok(Some(agent_response));
        }

        let agent_status = self.get_agent_status(deps.storage, env, account_id);

        // Return wrapped error if there was a problem
        if agent_status.is_err() {
            return Err(StdError::GenericErr {
                msg: agent_status.err().unwrap().to_string(),
            });
        }

        agent_response.status = agent_status.expect("Should have valid agent status");
        Ok(Some(agent_response))
    }

    /// Get a list of agent addresses
    pub(crate) fn query_get_agent_ids(&self, deps: Deps) -> StdResult<GetAgentIdsResponse> {
        let active: Vec<Addr> = self.agent_active_queue.load(deps.storage)?;
        let pending: Vec<Addr> = self.agent_pending_queue.load(deps.storage)?;

        Ok(GetAgentIdsResponse { active, pending })
    }

    // TODO: Change this to solid round-table implementation. Setup this simple version for PoC
    /// Get how many tasks an agent can execute
    /// TODO: Remove this function, replaced by balancer
    pub(crate) fn query_get_agent_tasks(
        &mut self,
        deps: Deps,
        env: Env,
        account_id: String,
    ) -> StdResult<Option<AgentTaskResponse>> {
        let account_id = deps.api.addr_validate(&account_id)?;
        let active = self.agent_active_queue.load(deps.storage)?;
        if !active.contains(&account_id) {
            // TODO: unsure if we can return AgentNotRegistered
            return Err(StdError::GenericErr {
                msg: AgentNotRegistered {}.to_string(),
            });
        }
        // Get all tasks (the final None means no limit when we take)
        let block_slots = self
            .block_slots
            .range(
                deps.storage,
                None,
                Some(Bound::inclusive(env.block.height)),
                cosmwasm_std::Order::Ascending,
            )
            .count();

        let time_slots = self
            .time_slots
            .range(
                deps.storage,
                None,
                Some(Bound::inclusive(env.block.time.nanos())),
                cosmwasm_std::Order::Ascending,
            )
            .count();

        if (block_slots, time_slots) == (0, 0) {
            return Ok(None);
        }

        self.balancer.get_agent_tasks(
            &deps,
            &env,
            &self.config,
            &self.agent_active_queue,
            account_id,
            (Some(block_slots as u64), Some(time_slots as u64)),
        )
    }

    /// Add any account as an agent that will be able to execute tasks.
    /// Registering allows for rewards accruing with micro-payments which will accumulate to more long-term.
    ///
    /// Optional Parameters:
    /// "payable_account_id" - Allows a different account id to be specified, so a user can receive funds at a different account than the agent account.
    pub fn register_agent(
        &self,
        deps: DepsMut,
        info: MessageInfo,
        env: Env,
        payable_account_id: Option<String>,
    ) -> Result<Response, ContractError> {
        if !info.funds.is_empty() {
            return Err(ContractError::CustomError {
                val: "Do not attach funds".to_string(),
            });
        }
        let c: Config = self.config.load(deps.storage)?;
        if c.paused {
            return Err(ContractError::ContractPaused {
                val: "Register agent paused".to_string(),
            });
        }

        let account = info.sender;

        // REF: https://github.com/CosmWasm/cw-tokens/tree/main/contracts/cw20-escrow
        // Check if native token balance is sufficient for a few txns, in this case 4 txns
        // TODO: Adjust gas & costs based on real usage cost
        let agent_wallet_balances = deps.querier.query_all_balances(account.clone())?;
        let gas_cost = calculate_required_amount(c.gas_action_fee, c.agent_fee)?;
        let unit_cost = c.gas_fraction.calculate(4 * gas_cost, 1)?;
        if !has_coins(
            &agent_wallet_balances,
            &Coin::new(unit_cost, c.native_denom),
        ) || agent_wallet_balances.is_empty()
        {
            return Err(ContractError::CustomError {
                val: "Insufficient funds".to_string(),
            });
        }

        let payable_id = if let Some(addr) = payable_account_id {
            deps.api.addr_validate(&addr)?
        } else {
            account.clone()
        };

        let mut active_agents: Vec<Addr> = self.agent_active_queue.load(deps.storage)?;
        let total_agents = active_agents.len();
        let agent_status = if total_agents == 0 {
            active_agents.push(account.clone());
            self.agent_active_queue.save(deps.storage, &active_agents)?;
            AgentStatus::Active
        } else {
            let mut pending_agents = self.agent_pending_queue.load(deps.storage)?;
            pending_agents.push(account.clone());
            self.agent_pending_queue
                .save(deps.storage, &pending_agents)?;
            AgentStatus::Pending
        };
        let agent = self.agents.update(
            deps.storage,
            &account,
            |a: Option<Agent>| -> Result<_, ContractError> {
                match a {
                    // make sure that account isn't already added
                    Some(_) => Err(ContractError::CustomError {
                        val: "Agent already exists".to_string(),
                    }),
                    None => {
                        Ok(Agent {
                            payable_account_id: payable_id,
                            balance: GenericBalance::default(),
                            total_tasks_executed: 0,
                            last_executed_slot: env.block.height,
                            // REF: https://github.com/CosmWasm/cosmwasm/blob/main/packages/std/src/types.rs#L57
                            register_start: env.block.time,
                        })
                    }
                }
            },
        )?;

        Ok(Response::new()
            .add_attribute("method", "register_agent")
            .add_attribute("agent_status", format!("{:?}", agent_status))
            .add_attribute("register_start", agent.register_start.nanos().to_string())
            .add_attribute("payable_account_id", agent.payable_account_id))
    }

    /// Update agent details, specifically the payable account id for an agent.
    pub fn update_agent(
        &self,
        deps: DepsMut,
        info: MessageInfo,
        _env: Env,
        payable_account_id: String,
    ) -> Result<Response, ContractError> {
        let payable_account_id = deps.api.addr_validate(&payable_account_id)?;
        let c: Config = self.config.load(deps.storage)?;
        if c.paused {
            return Err(ContractError::ContractPaused {
                val: "Register agent paused".to_string(),
            });
        }

        let agent = self.agents.update(
            deps.storage,
            &info.sender,
            |a: Option<Agent>| -> Result<_, ContractError> {
                match a {
                    Some(agent) => {
                        let mut ag = agent;
                        ag.payable_account_id = payable_account_id;
                        Ok(ag)
                    }
                    None => Err(ContractError::AgentNotRegistered {}),
                }
            },
        )?;

        Ok(Response::new()
            .add_attribute("method", "update_agent")
            .add_attribute("payable_account_id", agent.payable_account_id))
    }

    /// Allows an agent to withdraw all rewards, paid to the specified payable account id.
    pub(crate) fn withdraw_balances(
        &self,
        storage: &mut dyn Storage,
        agent_id: &Addr,
    ) -> Result<Vec<SubMsg>, ContractError> {
        let mut agent = self
            .agents
            .may_load(storage, agent_id)?
            .ok_or(AgentNotRegistered {})?;

        // This will send all token balances to Agent
        let (messages, balances) = send_tokens(&agent.payable_account_id, &agent.balance)?;
        agent.balance.checked_sub_generic(&balances)?;
        let mut config = self.config.load(storage)?;
        config
            .available_balance
            .checked_sub_native(&balances.native)?;
        self.agents.save(storage, agent_id, &agent)?;
        self.config.save(storage, &config)?;

        Ok(messages)
    }

    /// Allows an agent to withdraw all rewards, paid to the specified payable account id.
    pub fn withdraw_agent_balance(
        &self,
        deps: DepsMut,
        agent_id: &Addr,
    ) -> Result<Response, ContractError> {
        let messages = self.withdraw_balances(deps.storage, agent_id)?;

        Ok(Response::new()
            .add_attribute("method", "withdraw_agent_balance")
            .add_attribute("account_id", agent_id)
            .add_submessages(messages))
    }

    /// Allows an agent to accept a nomination within a certain amount of time to become an active agent.
    pub fn accept_nomination_agent(
        &self,
        deps: DepsMut,
        info: MessageInfo,
        env: Env,
    ) -> Result<Response, ContractError> {
        // Compare current time and Config's agent_nomination_begin_time to see if agent can join
        let c: Config = self.config.load(deps.storage)?;

        let time_difference =
            if let Some(nomination_start) = self.agent_nomination_begin_time.load(deps.storage)? {
                env.block.time.seconds() - nomination_start.seconds()
            } else {
                // No agents can join yet
                return Err(ContractError::CustomError {
                    val: "Not accepting new agents".to_string(),
                });
            };
        // Agent must be in the pending queue
        let pending_queue = self.agent_pending_queue.load(deps.storage)?;
        // Get the position in the pending queue
        if let Some(agent_position) = pending_queue
            .iter()
            .position(|address| address == &info.sender)
        {
            // It works out such that the time difference between when this is called,
            // and the agent nomination begin time can be divided by the nomination
            // duration and we get an integer. We use that integer to determine if an
            // agent is allowed to get let in. If their position in the pending queue is
            // less than or equal to that integer, they get let in.
            let max_index = time_difference.div(c.agent_nomination_duration as u64);
            if agent_position as u64 <= max_index {
                // Make this agent active
                // Update state removing from pending queue
                let mut pending_agents: Vec<Addr> = self.agent_pending_queue.load(deps.storage)?;
                // Remove this agent and all ahead of them in the queue (they missed out)
                for idx_to_remove in (0..=agent_position).rev() {
                    pending_agents.remove(idx_to_remove);
                }
                self.agent_pending_queue
                    .save(deps.storage, &pending_agents)?;

                // and adding to active queue
                let mut active_agents: Vec<Addr> = self.agent_active_queue.load(deps.storage)?;
                active_agents.push(info.sender.clone());
                self.agent_active_queue.save(deps.storage, &active_agents)?;

                // and update the config, setting the nomination begin time to None,
                // which indicates no one will be nominated until more tasks arrive
                self.agent_nomination_begin_time.save(deps.storage, &None)?;
                self.config.save(deps.storage, &c)?;
            } else {
                return Err(ContractError::CustomError {
                    val: "Must wait longer before accepting nomination".to_string(),
                });
            }
        } else {
            // Sender's address does not exist in the agent pending queue
            return Err(ContractError::AgentNotRegistered {});
        }
        // Find difference
        Ok(Response::new().add_attribute("method", "accept_nomination_agent"))
    }

    /// Removes the agent from the active set of agents.
    /// Withdraws all reward balances to the agent payable account id.
    pub fn unregister_agent(
        &self,
        storage: &mut dyn Storage,
        agent_id: &Addr,
    ) -> Result<Response, ContractError> {
        // Get withdraw messages, if any
        // NOTE: Since this also checks if agent exists, safe to not have redundant logic
        let messages = self.withdraw_balances(storage, agent_id)?;
        self.agents.remove(storage, agent_id);

        // Remove from the list of active agents if the agent in this list
        let mut active_agents: Vec<Addr> = self
            .agent_active_queue
            .may_load(storage)?
            .unwrap_or_default();
        if let Some(index) = active_agents.iter().position(|addr| *addr == *agent_id) {
            //Notify the balancer agent has been removed, to rebalance itself
            self.balancer.on_agent_unregister(
                storage,
                &self.config,
                &self.agent_active_queue,
                agent_id.clone(),
            );
            active_agents.remove(index);

            self.agent_active_queue.save(storage, &active_agents)?;
        } else {
            // Agent can't be both in active and pending vector
            // Remove from the pending queue
            let mut pending_agents: Vec<Addr> = self
                .agent_pending_queue
                .may_load(storage)?
                .unwrap_or_default();
            if let Some(index) = pending_agents.iter().position(|addr| addr == agent_id) {
                pending_agents.remove(index);
                self.agent_pending_queue.save(storage, &pending_agents)?;
            }
        }

        let responses = Response::new()
            .add_attribute("method", "unregister_agent")
            .add_attribute("account_id", agent_id);

        if messages.is_empty() {
            Ok(responses)
        } else {
            Ok(responses.add_submessages(messages))
        }
    }
}
