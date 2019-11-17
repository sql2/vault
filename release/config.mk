# config.mk
#
# config.mk contains constants and derived configuration that applies to
# building both layers and final packages.

# Only include the config once. This means we can include it in the header
# of each makefile, to allow calling them individually and when they call
# each other.
ifneq ($(CONFIG_INCLUDED),YES)
CONFIG_INCLUDED := YES

# Set SHELL to strict mode, in a way compatible with both old and new GNU make.
SHELL := /usr/bin/env bash -euo pipefail -c

# RELEASE_DIR is the absolute path to the dir containing all the
# release makefiles etc. typically this is 'release'.
RELEASE_DIR := $(shell dirname $(lastword $(MAKEFILE_LIST)))

# CACHE_ROOT is the build cache directory.
CACHE_ROOT ?= .buildcache

# ALWAYS_EXCLUDE_SOURCE prevents source from these directories from taking
# part in the SOURCE_ID, or from being sent to the builder image layers.
# This is important for allowing the head of master to build other commits
# where this build system has not been vendored.
#
# Source in RELEASE_DIR is encoded as PACKAGE_SPEC_ID and included in paths
# and cache keys. Source in .circleci/ should not do much more than call
# code in the release/ directory.
ALWAYS_EXCLUDE_SOURCE     := $(RELEASE_DIR)/ .circleci/
# ALWAYS_EXCLUD_SOURCE_GIT is git path filter parlance for the above.
ALWAYS_EXCLUDE_SOURCE_GIT := ':(exclude)$(RELEASE_DIR)/' ':(exclude).circleci/'

# Even though layers may have different Git revisions, based on the latest
# revision of their source, we always want to
# honour either HEAD or the specified PRODUCT_REVISION for compiling the
# final binaries, as this revision is the one picked by a human to form
# the release.
ifeq ($(PRODUCT_REVISION),)
# If PRODUCT_REVISION is empty (the default) we are concerned with building the
# current work tree, regardless of whether it is dirty or not. For local builds
# this is more convenient and more likely expected behaviour than having to commit
# just to perform a new build.
GIT_REF := HEAD
ALLOW_DIRTY ?= YES
else
# PRODUCT_REVISION is non-emtpy so treat it as a git commit ref and pull files
# directly from git rather than the work tree.
GIT_REF := $(PRODUCT_REVISION)
ALLOW_DIRTY := NO
endif

# End including config once only.
endif
