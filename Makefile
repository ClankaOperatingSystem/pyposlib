# make check: the tests, then the shared fixtures and poslib, differentially.
# It needs PyYAML, for the .pos reader: PYTHON names an interpreter that has it.
# make check-ipfs IPFS=path/to/ipfs: the CID fixtures against kubo, offline.
#
# The shared fixtures are poslib's: POSLIB names a checkout, else
# _deps/poslib is cloned here and brought to POSLIB_REF.

PYTHON     ?= python3
IPFS       ?= ipfs
POSLIB_URL ?= https://github.com/ClankaOperatingSystem/poslib.git
POSLIB_REF ?= master
POSLIB     ?= _deps/poslib

export POSLIB

.PHONY: check check-ipfs test formats sealing remote signin tree differential poslib

check: test formats sealing remote signin tree differential

test:
	$(PYTHON) -B test/test_archive_integrity.py

formats: poslib
	$(PYTHON) -B test/test_formats.py

sealing: poslib
	$(PYTHON) -B test/test_seal.py

remote: poslib
	$(PYTHON) -B test/test_remote.py

signin: poslib
	$(PYTHON) -B test/test_signin.py

tree: poslib
	$(PYTHON) -B test/test_tree.py

differential: poslib
	$(PYTHON) -B test/test_differential.py

check-ipfs: poslib
	$(PYTHON) -B test/check_ipfs.py $(IPFS)

poslib:
	@if [ "$(POSLIB)" = _deps/poslib ]; then \
	  [ -d _deps/poslib ] || git clone -q $(POSLIB_URL) _deps/poslib; \
	  git -C _deps/poslib fetch -q origin $(POSLIB_REF) && \
	  git -C _deps/poslib checkout -q --detach FETCH_HEAD; \
	fi
	@if [ -n "$$(command -v $${EMACS:-emacs})" ]; then $(MAKE) -s -C $(POSLIB) deps; fi
