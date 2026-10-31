#!/usr/bin/env bash
# The prompt-injection demo: the same gullible agent, without and with ironwrit.
# Run from anywhere: ./demo/run.sh
set -euo pipefail
cd "$(dirname "$0")"

banner() { printf '\n\033[1m== %s ==\033[0m\n\n' "$1"; }
step() { printf '\033[2m$ %s\033[0m\n' "$*"; }

cargo build --quiet -p ironwrit-cli -p ironwrit-demo
bin=../target/debug
ironwrit=$bin/ironwrit
demo=$bin/ironwrit-demo
rm -rf out && mkdir out

banner "Run A: agent -> tools, no gateway"
step "ironwrit-demo agent -- ironwrit-demo server"
"$demo" agent -- "$demo" server
echo
if [ -s out/outbox.jsonl ]; then
  echo "Outbox (out/outbox.jsonl): the secrets were emailed to the attacker:"
  cat out/outbox.jsonl
fi
rm -f out/outbox.jsonl

banner "Run B: agent -> ironwrit -> tools"
step "ironwrit keygen --out out/root"
"$ironwrit" keygen --out out/root
step "ironwrit mint --policy policy.dl --path docs=docs --ttl 1h"
"$ironwrit" mint --key out/root.key --policy policy.dl --path docs=docs --ttl 1h -o out/task.token
"$ironwrit" inspect out/task.token --pub out/root.pub
echo
gateway=("$ironwrit" run --root-pub out/root.pub --config ../ironwrit.toml
         --ledger out/ironwrit.db --gateway-key out/gateway.key)
step "ironwrit-demo agent -- ironwrit run --token \$(cat out/task.token) -- ironwrit-demo server"
"$demo" agent -- "${gateway[@]}" --token "$(cat out/task.token)" -- "$demo" server
echo
if [ -s out/outbox.jsonl ]; then
  echo "UNEXPECTED: mail was sent:" && cat out/outbox.jsonl && exit 1
fi
echo "Outbox: empty. Nothing was sent."

banner "The ledger proves it"
step "ironwrit log show"
"$ironwrit" log show --db out/ironwrit.db
echo
step "ironwrit log verify --pub out/gateway.pub"
"$ironwrit" log verify --db out/ironwrit.db --pub out/gateway.pub
echo
step "ironwrit log prove 3   # the denied send_email"
"$ironwrit" log prove 3 --db out/ironwrit.db --pub out/gateway.pub

banner "Run C: a summarizer sub-agent with a narrower token"
step "ironwrit attenuate out/task.token --check 'check if tool(\"fetch\")' --ttl 10m"
"$ironwrit" attenuate out/task.token --check 'check if tool("fetch")' --ttl 10m -o out/summarizer.token
"$demo" agent --name summarizer -- "${gateway[@]}" --token "$(cat out/summarizer.token)" -- "$demo" server
echo
step "ironwrit log show"
"$ironwrit" log show --db out/ironwrit.db
