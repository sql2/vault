# build.mk
#
# build.mk builds the packages defined in packages.lock, first building all necessary
# builder images.
#
# NOTE: This file should always run as though it were in the repo root, so all paths
# are relative to the repo root.

SHELL := /usr/bin/env bash -euo pipefail -c

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

### BEGIN Package building rules.
###
### This section dictates how we invoke the builder conainer to build the output package.

# PACKAGE_OUT_ROOT is the root directory where the final packages will be written to.
PACKAGE_OUT_ROOT ?= dist

### Default package parameters when not explicitly set.
### This is closely equivalent to 'make dev' in the top-level Makefile.
### For releases, these are overrdden by entries in packages.lock.

GOOS ?= $(shell go env GOOS 2>/dev/null || echo linux)
GOARCH ?= $(shell go env GOARCH 2>/dev/null || echo amd64)
CGO_ENABLED ?= 0
GO111MODULE ?= off

# GO_BUILD_TAGS is a comma-separated list of Go build tags, passed to -tags flag of 'go build'.
GO_BUILD_TAGS ?= vault

### Package parameters.

# BINARY_NAME is literally the name of the product's binary file.
BINARY_NAME ?= vault
# PRODUCT_NAME is the top-level name of all editions of this product.
PRODUCT_NAME ?= vault
PRODUCT_VERSION ?= 0.0.0-dev
# BUILD_VERSION is the major/minor/prerelease fields of the version.
PRODUCT_VERSION_MMP ?= 0.0.0
# BUILD_PRERELEASE is the prerelease field of the version. If nonempty, it must begin with a -.
PRODUCT_VERSION_PRE ?= -dev
# EDITION is used to differentiate alternate builds of the same commit, which may differ in
# terms of build tags or other build inputs. EDITION should always form part of the BUNDLE_NAME.
EDITION ?=

### Calculated package parameters.

# BUNDLE_NAME is the name of the release bundle.
BUNDLE_NAME ?= $(PRODUCT_NAME)$(EDITION)
# PACKAGE_NAME is the unique name of a specific build of this product.
PACKAGE_NAME ?= $(BUNDLE_NAME)_$(PRODUCT_VERSION)_$(GOOS)_$(GOARCH)
PACKAGE_FILENAME ?= $(PACKAGE_NAME).zip
# PACKAGE is the zip file containing a specific binary.
PACKAGE = $(OUT_DIR)/$(PACKAGE_FILENAME)

# LDFLAGS: These linker commands inject build metadata into the binary.
LDFLAGS += -X github.com/hashicorp/vault/sdk/version.GitCommit="$(PACKAGE_SOURCE_ID)"
LDFLAGS += -X github.com/hashicorp/vault/sdk/version.Version="$(PRODUCT_VERSION_MMP)"
LDFLAGS += -X github.com/hashicorp/vault/sdk/version.VersionPrerelease="$(PRODUCT_VERSION_PRE)"

# OUT_DIR tells the Go toolchain where to place the binary.
OUT_DIR := $(PACKAGE_OUT_ROOT)/$(PACKAGE_NAME)/$(PACKAGE_SOURCE_ID)/$(PACKAGE_SPEC_ID)

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
PACKAGE_PATH := $(OUT_DIR)/$(PACKAGE_FILENAME) 

### Docker run command configuration.

DOCKER_SHELL := /bin/bash -euo pipefail -c

BUILD_CONTAINER_NAME := build-$(PACKAGE_NAME)
DOCKER_RUN_FLAGS := --name $(BUILD_CONTAINER_NAME)
# DOCKER_RUN_COMMAND ties everything together to build the final package as a
# single docker run invocation.
DOCKER_RUN_COMMAND = docker run $(DOCKER_RUN_FLAGS) $(BUILD_LAYER_IMAGE_NAME) $(DOCKER_SHELL) "$(BUILD_COMMAND) && $(ARCHIVE_COMMAND)"
DOCKER_CP_COMMAND = docker cp $(BUILD_CONTAINER_NAME):/$(PACKAGE_PATH) $(PACKAGE_PATH)

.PHONY: build
build: $(PACKAGE)
	@echo $<

# PACKAGE assumes 'make static-image' has already been run.
# It does not depend on the static image, as this simplifies cache re-use
# on circleci.
$(PACKAGE):
	@# Instead of depending on the static image, we just check for its marker file
	@# here. This allows us to skip checking the whole dependency tree, which means
	@# we can buiild the package with just the static image, not relying on any of
	@# the other base images to be present.
	@if [ ! -f $(BUILD_LAYER_IMAGE) ]; then $(MAKE) -f $(THIS_FILE) $(BUILD_LAYER_IMAGE); fi
	@mkdir -p $$(dirname $@)
	@echo "==> Building package: $@"
	@rm -rf ./$(OUT_DIR)
	@mkdir -p ./$(OUT_DIR)
	@docker rm -f $(BUILD_CONTAINER_NAME) > /dev/null 2>&1 || true # Speculative cleanup.
	$(DOCKER_RUN_COMMAND)
	$(DOCKER_CP_COMMAND)
	@docker rm -f $(BUILD_CONTAINER_NAME) # Imperative cleanup.
