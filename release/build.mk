# build.mk
#
# build.mk builds the packages defined in packages.lock, first building all necessary
# builder images.
#
# NOTE: This file should always run as though it were in the repo root, so all paths
# are relative to the repo root.

SHELL := /usr/bin/env bash -euo pipefail -c

# Make sure we have all the necessary inputs.
# Ensure all of these are set in packages.lock
ifeq ($(BUILDER_LAYER_ID),)
$(error You must set BUILDER_LAYER_ID, try invoking 'make build' instead.)
endif
ifeq ($(BINARY_NAME),)
$(error You must set BINARY_NAME, try invoking 'make build' instead.)
endif
ifeq ($(BUNDLE_NAME),)
$(error You must set BUNDLE_NAME, try invoking 'make build' instead.)
endif
ifeq ($(PRODUCT_VERSION),)
$(error You must set PRODUCT_VERSION, try invoking 'make build' instead.)
endif
ifeq ($(PRODUCT_VERSION_PRE),)
$(error You must set PRODUCT_VERSION_PRE, try invoking 'make build' instead.)
endif
ifeq ($(PRODUCT_VERSION_MMP),)
$(error You must set PRODUCT_VERSION_MMP, try invoking 'make build' instead.)
endif
ifeq ($(BUILD_JOB_NAME),)
$(error You must set BUILD_JOB_NAME try invoking 'make build' instead.)
endif
ifeq ($(PACKAGE_NAME),)
$(error You must set PACKAGE_NAME, try invoking 'make build' instead.)
endif
ifeq ($(BUILDER_LAYER_ID),)
$(error You must set BUILDER_LAYER_ID, try invoking 'make build' instead.)
endif
ifeq ($(PACKAGE_SPEC_ID),)
$(error You must set PACKAGE_SPEC_ID, try invoking 'make build' instead.)
endif

CACHE_ROOT := .buildcache

THIS_FILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(shell dirname $(THIS_FILE))

# ALWAYS_EXCLUDE_SOURCE prevents source from these directories from taking
# part in the SOURCE_ID, or from being sent to the builder image layers.
# This is important for allowing the head of master to build other commits
# where this build system has not been vendored.
#
# Source in release/ is encoded as PACKAGE_SPEC_ID and included in paths
# and cache keys. Source in .circleci/ should not do much more than call
# code in the release/ directory.
ALWAYS_EXCLUDE_SOURCE     := release/ .circleci/
# ALWAYS_EXCLUD_SOURCE_GIT is git path filter parlance for the above.
ALWAYS_EXCLUDE_SOURCE_GIT := ':(exclude)release/' ':(exclude).circleci/'

# DOCKER_LAYER_LIST is used to dump the name of every docker ref in use
# by all of the current builder images. By running 'docker save' against
# this list, we end up with a tarball that can pre-populate the docker
# cache to avoid unnecessary rebuilds.
DOCKER_LAYER_LIST := $(CACHE_ROOT)/docker-layer-list
DOCKER_BUILDER_CACHE := $(CACHE_ROOT)/docker-builder-cache.tar.gz

# Even though layers may have different Git revisions, we always want to
# honour either HEAD or the specified PRODUCT_REVISION for compiling the
# final binaries, as this revision is the one picked by a human to form
# the release.
ifeq ($(PRODUCT_REVISION),)
GIT_REF := HEAD
ALLOW_DIRTY ?= YES
DIRTY := $(shell git diff --exit-code $(GIT_REF) -- $(ALWAYS_EXCLUDE_SOURCE_GIT) > /dev/null 2>&1 || echo "dirty_")
PACKAGE_SOURCE_ID := $(DIRTY)$(shell git rev-parse $(GIT_REF))
else
GIT_REF := $(PRODUCT_REVISION)
ALLOW_DIRTY := NO
PACKAGE_SOURCE_ID := $(shell git rev-parse $(GIT_REF))
endif

DOCKERFILES_DIR := $(THIS_DIR)/layers.lock

# Include the layers driver.
include $(THIS_DIR)/layer.mk

# Include the generated instructions to build each layer.
include $(shell find release/layers.lock -name '*.mk')

UPDATE_MARKERS_OUTPUT := $(strip $(foreach L,$(LAYERS),$(shell $(call $(L)_UPDATE_MARKER_FILE))))
ifneq ($(UPDATE_MARKERS_OUTPUT),)
$(info $(UPDATE_MARKERS_OUTPUT))
endif

write-cache-keys: $(addsuffix -write-cache-key,$(LAYERS))
	@echo "==> All cache keys written."

build-all-layers: $(addsuffix -image,$(LAYERS))
	@echo "==> All builder layers built."

save-all-layers: $(DOCKER_BUILDER_CACHE)
	@ls -lh $<
	
	# TODO: Now we have saved the builder cache, we need to write a cache
	# key in the correct order to ensure CircleCI's prefix match is efficient.

$(DOCKER_BUILDER_CACHE): $(addsuffix -layer-refs,$(LAYERS))
	@cat $(addsuffix /image.layer_refs,$(LAYER_CACHES)) | sort | uniq > $(DOCKER_LAYER_LIST)
	@cat $(DOCKER_LAYER_LIST) | xargs docker save | gzip > $(DOCKER_BUILDER_CACHE)

.PHONY: debug
debug: $(addsuffix -debug,$(LAYERS))

# PACKAGE_OUT_ROOT is the root directory where the final packages will be written to.
PACKAGE_OUT_ROOT ?= dist

# LDFLAGS: These linker commands inject build metadata into the binary.
LDFLAGS += -X github.com/hashicorp/vault/sdk/version.GitCommit="$(PACKAGE_SOURCE_ID)"
LDFLAGS += -X github.com/hashicorp/vault/sdk/version.Version="$(PRODUCT_VERSION_MMP)"
LDFLAGS += -X github.com/hashicorp/vault/sdk/version.VersionPrerelease="$(PRODUCT_VERSION_PRE)"

# OUT_DIR tells the Go toolchain where to place the binary.
OUT_DIR := $(PACKAGE_OUT_ROOT)/$(PACKAGE_NAME)/$(PACKAGE_SOURCE_ID)/$(PACKAGE_SPEC_ID)
PACKAGE_FILENAME := $(PACKAGE_NAME).zip
# PACKAGE is the zip file containing a specific binary.
PACKAGE := $(OUT_DIR)/$(PACKAGE_FILENAME)

# GO_BUILD_VARS are environment variables affecting the go build
# command that will be passed through to the go build command inside the
# build container. This is a hand-picked list, because some like GOPATH you
# probably do not want the container build to inherit.
#
# Usually, you will be building one of the packages defined in packages.yml
# which should set the necessary vars for a given package.
#
# Any of these which are SET (even if empty) are passed through to 'go build'.
# Any which are not set will have default values on the build image.
GO_BUILD_VARS := \
	AR                      CC                      CGO_CFLAGS \
	CGO_CFLAGS_ALLOW        CGO_CFLAGS_DISALLOW     CGO_CPPFLAGS \
	CGO_CPPFLAGS_ALLOW      CGO_CPPFLAGS_DISALLOW   CGO_CXXFLAGS \
	CGO_CXXFLAGS_ALLOW      CGO_CXXFLAGS_DISALLOW   CGO_ENABLED \
	CGO_FFLAGS              CGO_FFLAGS_ALLOW        CGO_FFLAGS_DISALLOW \
	CGO_LDFLAGS             CGO_LDFLAGS_ALLOW       CGO_LDFLAGS_DISALLOW \
	CXX                     GCCGO                   GCCGOTOOLDIR \
	GIT_ALLOW_PROTOCOL      GO386                   GOARCH \
	GOARM                   GOBIN                   GOCACHE \
	GOFLAGS                 GOMIPS                  GOMIPS64 \
	GOOS                    GOPROXY                 GORACE \
	GO_EXTLINK_ENABLED      PKG_CONFIG

# For any GO_BUILD_VARS that are explicitly set, stick them in GO_BUILD_ENV
# for passing to 'go build'.
GO_BUILD_ENV := $(shell \
	for VAR in $(GO_BUILD_VARS); do \
		[ -z "$${!VAR+x}" ] || echo "$$VAR='$${!VAR}'"; \
	done; \
)

# BUILD_COMMAND compiles the Go binary.
BUILD_COMMAND := \
	$(GO_BUILD_ENV) \
	go build -v \
	-tags '$(GO_BUILD_TAGS)' \
	-ldflags '$(LDFLAGS)' \
	-o /$(OUT_DIR)/$(BINARY_NAME)

# ARCHIVE_COMMAND creates the package archive from the binary.
ARCHIVE_COMMAND := cd /$(OUT_DIR) && zip $(PACKAGE_FILENAME) $(BINARY_NAME)

### Docker run command configuration.

DOCKER_SHELL := /bin/bash -euo pipefail -c

BUILD_CONTAINER_NAME := build-$(PACKAGE_NAME)
DOCKER_RUN_FLAGS := --name $(BUILD_CONTAINER_NAME)
# DOCKER_RUN_COMMAND ties everything together to build the final package as a
# single docker run invocation.
DOCKER_RUN_COMMAND = docker run $(DOCKER_RUN_FLAGS) $(BUILD_LAYER_IMAGE_NAME) $(DOCKER_SHELL) "$(BUILD_COMMAND) && $(ARCHIVE_COMMAND)"
DOCKER_CP_COMMAND = docker cp $(BUILD_CONTAINER_NAME):/$(PACKAGE) $(PACKAGE)

.PHONY: package
package: $(PACKAGE)
	@echo $<

# PACKAGE builds the package.
$(PACKAGE): $(BUILD_LAYER_IMAGE)
	@mkdir -p $$(dirname $@)
	@echo "==> Building package: $@"
	@rm -rf ./$(OUT_DIR)
	@mkdir -p ./$(OUT_DIR)
	@docker rm -f $(BUILD_CONTAINER_NAME) > /dev/null 2>&1 || true # Speculative cleanup.
	$(DOCKER_RUN_COMMAND)
	$(DOCKER_CP_COMMAND)
	@docker rm -f $(BUILD_CONTAINER_NAME)
