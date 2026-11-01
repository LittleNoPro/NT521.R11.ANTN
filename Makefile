# CVE-GENIE reproduction project (NT521.R11.ANTN) — one-command targets.
# Everything here is FREE (no paid API). Requires: Docker, the ./env venv.
PY := env/bin/python
CVE ?= CVE-2024-4340

.PHONY: help all corpus replay processor manual agent-3b agent-7b report demo clean

help:
	@echo "Targets:"
	@echo "  make corpus     - recompute paper's aggregate numbers from 429 artifacts (+charts)"
	@echo "  make replay     - replay published exploit+verifier in Docker (3 CVEs -> flag)"
	@echo "  make processor  - run the live Data Processor on \$$CVE"
	@echo "  make manual     - run our hand-written exploit+verifier (+patched control)"
	@echo "  make agent-3b   - local Qwen2.5-3B Exploiter agent on \$$CVE"
	@echo "  make agent-7b   - local Qwen2.5-7B Exploiter agent on \$$CVE (partial GPU offload)"
	@echo "  make report     - build report/report.pdf (lualatex)"
	@echo "  make demo       - interactive end-to-end demo"
	@echo "  make all        - corpus + replay + report"

all: corpus replay report

corpus:
	$(PY) experiments/corpus_analysis.py

replay:
	bash repro/artifacts/run_all.sh

processor:
	cd cve-genie/src && ../../$(PY) ./data/scripts/cve_data.py \
	  --cve_id $(CVE) --output_path ../../repro/processor/$(CVE).json

manual:
	docker build -q -t cve-manual repro/manual/$(CVE) >/dev/null
	docker run --rm cve-manual

agent-3b:
	$(PY) local_agent/agent.py --cve $(CVE) --tag make

# 7B needs partial offload on a 6 GB GPU; LLM_NGL caps GPU layers, rest on CPU.
agent-7b:
	LLM_GGUF=local_agent/models/Qwen2.5-7B-Instruct-Q4_K_M.gguf LLM_NGL=20 \
	  $(PY) local_agent/agent.py --cve $(CVE) --tag make7b

report:
	cd report && bash build.sh

demo:
	bash demo/run_demo.sh

clean:
	rm -f report/*.aux report/*.log report/*.out report/*.toc report/b?.log
