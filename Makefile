# make check: the tests, then the shared fixtures and poslib, differentially.
# make check-ipfs IPFS=path/to/ipfs: the CID fixtures against kubo, offline.
#
# The shared fixtures are poslib's: POSLIB names a checkout, else poslib/
# is cloned here and brought to POSLIB_REF.

PYTHON     ?= python3
IPFS       ?= ipfs
POSLIB_URL ?= https://github.com/monkeypants/poslib.git
POSLIB_REF ?= master
POSLIB     ?= poslib

export POSLIB

.PHONY: check check-ipfs test formats differential poslib

check: test formats differential

test:
	$(PYTHON) -B test/test_archive_integrity.py

formats: poslib
	$(PYTHON) -B test/test_formats.py

differential: poslib
	$(PYTHON) -B test/test_differential.py

check-ipfs: poslib
	$(PYTHON) -B test/check_ipfs.py $(IPFS)

poslib:
	@if [ "$(POSLIB)" = poslib ]; then \
	  [ -d poslib ] || git clone -q $(POSLIB_URL) poslib; \
	  git -C poslib fetch -q origin $(POSLIB_REF) && \
	  git -C poslib checkout -q --detach FETCH_HEAD; \
	fi
