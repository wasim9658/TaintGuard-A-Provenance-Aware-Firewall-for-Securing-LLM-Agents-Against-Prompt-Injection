# erpguard: taint-tracking firewall for a college ERP agent

Tags every value by trust level (user / system-of-record / untrusted) and blocks privileged tool calls
(send email, pay fee, leave request, exam form, contact update) when untrusted text influenced their
arguments. Enforcement is deterministic Python: **no LLM in the enforcement path**.

Research question: coarse taint ("agent saw anything untrusted, so block everything") over-blocks.
Do argument-level provenance + typed declassifiers keep the security and lose less utility?

## Quickstart (VS Code)
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q                          # 5 tests
python -m evaluation.run_eval      # prints results table, fills erpguard.db
python -m dashboard.app            # http://127.0.0.1:5000
```
Open the folder in VS Code, select the `.venv` interpreter, and use Run and Debug (launch configs included).

## Layout
- `erpguard/` labels, policies (+declassifiers), provenance modes, engine, agent loop, SQLite store
- `erp/` mock ERP + tools (output labels are fixed in tool code, never from output text)
- `evaluation/` datasets (8 clean, 12 mixed benign tasks, 24 attacks), simulated injectable agent, harness
- `dashboard/` Flask app: summary, event table, event detail with highlighted injected text, mode comparison

## Modes compared
`none`, `keyword` (regex baseline), `coarse`, `match` (taints only values found in untrusted text),
`hybrid-nodecl` (ablation), `hybrid` (positive attribution + declassifiers + coarse fallback for free text).

## Reading the results
`ASR` = attacker goal reached in ERP state (not model words). `mixed over-block` = benign tasks that read untrusted
content and then had a legitimate privileged call blocked. The evaluation drives a *simulated worst-case gullible agent*
so results are deterministic; they show the policy logic, not real-LLM behaviour. Treat as a harness and a starting point.

## Real LLM
`pip install -e ".[llm]"`, set your provider key, then
`python -m erpguard.live --model openai:gpt-4o-mini --inject notice "ACTION: ..." "Read my notices"`.
`LangChainPlanner` (erpguard/agent.py) is untested against live providers; check current LangChain docs.
To evaluate a real model, write a runner that swaps `GulliblePlanner` for `LangChainPlanner`, pins model/temperature, and uses 3-5 seeds.

## Next steps
Grow `MIXED` and `ATTACKS`, add adaptive attacks written against the firewall, try a quarantine (dual-LLM) mode,
adapt a slice of AgentDojo. See SECURITY.md for known limits.
