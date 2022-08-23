#!/bin/bash
set -ex

cd "$(dirname "$0")/.."

# In case of M1 MacBook use rust-optimizer-arm64 instead of rust-optimizer
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/rust-optimizer-arm64:0.12.6

NODE="--node https://rpc.uni.juno.deuslabs.fi:443"
TXFLAG="--node https://rpc.uni.juno.deuslabs.fi:443 --chain-id uni-3 --gas-prices 0.025ujunox --gas auto --gas-adjustment 1.3 --broadcast-mode block"

RULES_CONTRACT=$1

# Create wallets and make sure they have some JUNOX
OWNER=owner$RANDOM
AGENT=agent$RANDOM
USER=user$RANDOM

junod keys add $OWNER
junod keys add $AGENT
junod keys add $USER

# Make sure they have some JUNOX
JSON=$(jq -n --arg addr $(junod keys show -a $OWNER) '{ denom:"ujunox","address":$addr}') && \
  curl -X POST --header "Content-Type: application/json" --data "$JSON" https://faucet.uni.juno.deuslabs.fi/credit && echo
JSON=$(jq -n --arg addr $(junod keys show -a $AGENT) '{ denom:"ujunox","address":$addr}') && \
  curl -X POST --header "Content-Type: application/json" --data "$JSON" https://faucet.uni.juno.deuslabs.fi/credit && echo
JSON=$(jq -n --arg addr $(junod keys show -a $USER) '{ denom:"ujunox","address":$addr}') && \
  curl -X POST --header "Content-Type: application/json" --data "$JSON" https://faucet.uni.juno.deuslabs.fi/credit && echo

echo "Created $OWNER with 10 JUNOX balance"
echo "Created $AGENT with 10 JUNOX balance"
echo "Created $USER with 10 JUNOX balance"

# In case of M1 MacBook replace cw_croncat.wasm with cw_croncat-aarch64.wasm 
RES=$(junod tx wasm store artifacts/cw_croncat-aarch64.wasm --from $OWNER $TXFLAG -y --output json -b block)
CODE_ID=$(echo $RES | jq -r '.logs[0].events[-1].attributes[0].value')

# Instantiate
INIT='{"denom":"ujunox"}'
junod tx wasm instantiate $CODE_ID "$INIT" --from $OWNER --label "croncat" $TXFLAG -y --no-admin
CONTRACT=$(junod query wasm list-contract-by-code $CODE_ID $NODE --output json | jq -r '.contracts[-1]')

# Now we can register an agent, create tasks and execute a task
# Register an agent
REGISTER_AGENT='{"register_agent":{}}'
junod tx wasm execute $CONTRACT "$REGISTER_AGENT" --from $AGENT $TXFLAG -y

MSG='{"get_balance":{"address":"'$(junod keys show $USER -a)'","denom":"ujunox"}}'
ENCODED_MSG=$(echo $MSG | base64)

# Create a task
STAKE='{
  "create_task": {
    "task": {
      "interval": "Immediate",
      "boundary": null,
      "cw20_coins": [],
      "stop_on_fail": false,
      "actions": [
        {
          "msg": {
            "staking": {
              "delegate": {
                "validator": "juno14vhcdsyf83ngsrrqc92kmw8q9xakqjm0ff2dpn",
                "amount": {
                  "denom": "ujunox",
                  "amount": "1000000"
                }
              }
            }
          },
          "gas_limit": 150000
        }
      ],
      "rules": [
        {
          "contract_addr": "'$RULES_CONTRACT'",
          "msg": "'$ENCODED_MSG'"
        }
      ]
    }
  }
}'
junod tx wasm execute $CONTRACT "$STAKE" --amount 1000000ujunox --from $USER $TXFLAG -y

# See tasks with rules
GET_TASKS_WITH_RULES='{"get_tasks_with_rules":{}}'
TASKS_WITH_RULES=$(junod query wasm contract-state smart $CONTRACT "$GET_TASKS_WITH_RULES" $NODE --output json)
TASK_HASH=$(echo $TASKS_WITH_RULES | jq -r '.data[0].task_hash')

# proxy_call
sleep 10      # is needed to make sure this call in the next block 
PROXY_CALL='{"proxy_call":{"task_hash":"'$TASK_HASH'"}}'
junod tx wasm execute $CONTRACT "$PROXY_CALL" --from $AGENT $TXFLAG -y

junod query wasm contract-state smart $CONTRACT "$GET_TASKS_WITH_RULES" $NODE

echo "CONTRACT CODEID - $CODE_ID"
echo "CONTRACT $CONTRACT"
echo "OWNER $OWNER"
echo "AGENT $AGENT"
echo "USER $USER"

