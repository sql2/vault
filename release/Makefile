SHELL := /usr/bin/env bash -euo pipefail -c

.PHONY: packages build

packages:
	@# Remove layers.lock entirely to avoid buildup of old layers.
	@# Easier to do that here than in packages.mk.
	@rm -rf layers.lock
	@$(MAKE) -f packages.mk lock

commands:
	@$(MAKE) -f packages.mk commands

build:
	@# Run the build makefile as if it were in the repo root.
	@$(MAKE) -C ../ -f release/build.mk build

build-all: commands
	cd ../ && $(SHELL) "$$(cat release/.tmp/all-commands.sh)"
