PYTHON ?= python3
export PYTHONPATH := $(CURDIR)/src$(if $(PYTHONPATH),:$(PYTHONPATH))

.PHONY: verify test lint build native-smoke reproduce-chacha20 reproduce-speck reproduce-threefish

verify:
	"$(PYTHON)" -m fullround_key_recovery.cli all --pretty

test:
	"$(PYTHON)" -m pytest

lint:
	ruff check src tests

build:
	"$(PYTHON)" -m build

native-smoke:
	./scripts/native_smoke.sh

reproduce-chacha20:
	./scripts/reproduce_full_search.sh chacha20

reproduce-speck:
	./scripts/reproduce_full_search.sh speck32_64

reproduce-threefish:
	./scripts/reproduce_full_search.sh threefish256
