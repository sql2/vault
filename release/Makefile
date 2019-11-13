SHELL := /usr/bin/env bash -euo pipefail -c

.PHONY: packages build

packages:
	@$(MAKE) -f packages.mk lock

commands:
	@$(MAKE) -f packages.mk commands

build:
	@# Run the build makefile as if it were in the repo root.
	@$(MAKE) -C ../ -f release/build.mk build

build-all: commands
	cd ../ && $(SHELL) "$$(cat release/.tmp/all-commands.sh)"
