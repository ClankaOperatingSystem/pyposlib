# make check: the tests.

PYTHON ?= python3

.PHONY: check

check:
	$(PYTHON) -B test/test_archive_integrity.py
