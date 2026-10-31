# The prompt-injection demo: the same gullible agent, without and with ironwrit.
# Run from anywhere: powershell -ExecutionPolicy Bypass -File demo\run.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Banner($text) { Write-Host "`n== $text ==`n" -ForegroundColor White }
function Step($text) { Write-Host "`$ $text" -ForegroundColor DarkGray }
function Check { if ($LASTEXITCODE -ne 0) { throw "command failed with exit code $LASTEXITCODE" } }

cargo build --quiet -p ironwrit-cli -p ironwrit-demo; Check
$ironwrit = Join-Path $PSScriptRoot '..\target\debug\ironwrit.exe'
$demo = Join-Path $PSScriptRoot '..\target\debug\ironwrit-demo.exe'
if (Test-Path out) { Remove-Item -Recurse -Force out }
New-Item -ItemType Directory out | Out-Null

Banner 'Run A: agent -> tools, no gateway'
Step 'ironwrit-demo agent -- ironwrit-demo server'
& $demo agent -- $demo server; Check
if ((Test-Path out\outbox.jsonl) -and (Get-Item out\outbox.jsonl).Length -gt 0) {
    Write-Host "`nOutbox (out\outbox.jsonl): the secrets were emailed to the attacker:"
    Get-Content out\outbox.jsonl
    Remove-Item out\outbox.jsonl
}

Banner 'Run B: agent -> ironwrit -> tools'
Step 'ironwrit keygen --out out/root'
& $ironwrit keygen --out out/root; Check
Step 'ironwrit mint --policy policy.dl --path docs=docs --ttl 1h'
& $ironwrit mint --key out/root.key --policy policy.dl --path docs=docs --ttl 1h -o out/task.token; Check
& $ironwrit inspect out/task.token --pub out/root.pub; Check
$gateway = @('run', '--root-pub', 'out/root.pub', '--config', '../ironwrit.toml',
             '--ledger', 'out/ironwrit.db', '--gateway-key', 'out/gateway.key')
$token = (Get-Content out\task.token -Raw).Trim()
Step 'ironwrit-demo agent -- ironwrit run --token $TOKEN -- ironwrit-demo server'
& $demo agent -- $ironwrit @gateway --token $token -- $demo server; Check
if ((Test-Path out\outbox.jsonl) -and (Get-Item out\outbox.jsonl).Length -gt 0) {
    Get-Content out\outbox.jsonl
    throw 'UNEXPECTED: mail was sent'
}
Write-Host "`nOutbox: empty. Nothing was sent."

Banner 'The ledger proves it'
Step 'ironwrit log show'
& $ironwrit log show --db out/ironwrit.db; Check
Step 'ironwrit log verify --pub out/gateway.pub'
& $ironwrit log verify --db out/ironwrit.db --pub out/gateway.pub; Check
Step 'ironwrit log prove 3   # the denied send_email'
& $ironwrit log prove 3 --db out/ironwrit.db --pub out/gateway.pub; Check

Banner 'Run C: a summarizer sub-agent with a narrower token'
Step "ironwrit attenuate out/task.token --check 'check if tool(`"fetch`")' --ttl 10m"
$check = 'check if tool("fetch")'
# Before 7.3, PowerShell drops unescaped quotes when calling native programs.
if ($PSVersionTable.PSVersion -lt [version]'7.3') { $check = $check -replace '"', '\"' }
& $ironwrit attenuate out/task.token --check $check --ttl 10m -o out/summarizer.token; Check
$sub = (Get-Content out\summarizer.token -Raw).Trim()
& $demo agent --name summarizer -- $ironwrit @gateway --token $sub -- $demo server; Check
Step 'ironwrit log show'
& $ironwrit log show --db out/ironwrit.db; Check
