# Convenience targets for the optimized build.
#
#   make test      run the upstream suite + the differential suite
#   make lint      ruff check + format check
#   make bench     A/B measurement (needs ../upstream-itsdangerous)
#   make figures   re-render assets/*.png from bench/results/*.json

PYTHON ?= python
UPSTREAM ?= ../upstream-itsdangerous

.PHONY: test test-upstream test-differential lint bench aa ablate gate figures clean

test: test-upstream test-differential

test-upstream:
	PYTHONPATH=src $(PYTHON) -m pytest tests -q --ignore=tests/test_differential.py

test-differential:
	PYTHONPATH=src UPSTREAM_DIR=$(UPSTREAM) $(PYTHON) -m pytest tests/test_differential.py -q

lint:
	$(PYTHON) -m ruff check src tests bench assets
	$(PYTHON) -m ruff format --check src tests

bench:
	$(PYTHON) bench/bench.py --upstream $(UPSTREAM) --optimized . \
		--rounds 31 --target-ms 12 --out bench/results/ab.json

aa:
	$(PYTHON) bench/bench.py --a-a --upstream . \
		--rounds 31 --target-ms 12 --out bench/results/aa.json

ablate:
	$(PYTHON) bench/ablation_build.py . ablation
	$(PYTHON) bench/ablate.py

gate:
	$(PYTHON) bench/measure_gate.py

figures:
	$(PYTHON) assets/make_figures.py

clean:
	rm -rf ablation build dist .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
