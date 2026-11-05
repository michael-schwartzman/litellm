#!/usr/bin/env bash
set -uo pipefail
label="$1"
mkdir -p "$GITHUB_COPILOT_TOKEN_DIR"
uv run python litellm/proxy/proxy_cli.py --config poc/proxy_config.yaml --port 4000 --num_workers 2 > "proxy-$label.log" 2>&1 &
pid=$!
for _ in $(seq 1 90); do curl -sf -o /dev/null http://127.0.0.1:4000/health/liveliness && break; sleep 2; done
echo "== [$label] proxy workers: $(pgrep -f 'proxy_cli.py' | wc -l) processes"
call() {
  local name="$1" path="$2" body="$3" filter="$4"
  local out code
  out=$(curl -s -w '\n%{http_code}' "http://127.0.0.1:4000$path" -H 'Authorization: Bearer sk-poc-local' -H 'Content-Type: application/json' -d "$body")
  code=$(tail -n1 <<<"$out")
  echo "== [$label] $name -> HTTP $code"
  head -n -1 <<<"$out" | jq -c "$filter" 2>/dev/null || head -n -1 <<<"$out" | head -c 400; echo
}
call "chat gpt-4.1" /v1/chat/completions '{"model":"copilot-gpt","messages":[{"role":"user","content":"Reply with exactly: s2s ok"}],"max_tokens":10}' '{model, content: .choices[0].message.content, usage: .usage.total_tokens} // .error'
call "chat claude-sonnet-5" /v1/chat/completions '{"model":"copilot-claude","messages":[{"role":"user","content":"Reply with exactly: s2s ok"}],"max_tokens":20}' '{model, content: .choices[0].message.content} // .error'
call "chat stream" /v1/chat/completions '{"model":"copilot-gpt","stream":true,"messages":[{"role":"user","content":"Reply with exactly: s2s ok"}],"max_tokens":10}' '.'
call "responses gpt-5.6-luna" /v1/responses '{"model":"copilot-responses","input":"Reply with exactly: s2s ok"}' '{model, status, text: ([.output[]? | select(.type=="message") | .content[0].text] | first)} // .error'
call "anthropic messages claude-sonnet-5" /v1/messages '{"model":"copilot-claude","max_tokens":20,"messages":[{"role":"user","content":"Reply with exactly: s2s ok"}]}' '{model, text: .content[0].text} // .error'
kill $pid; wait $pid 2>/dev/null
if grep -E -o 'ghs_[A-Za-z0-9]{8,}' "proxy-$label.log" >/dev/null; then echo "!! token leaked in proxy log"; exit 1; fi
echo "== [$label] proxy log has no installation token"
