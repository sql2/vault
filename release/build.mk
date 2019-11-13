# build.mk
#
# build.mk defines the builder image layers, as well as the final build instructions we pass to
# the final layer (static) to produce the various packages.

SHELL := /usr/bin/env bash -euo pipefail -c

THIS_FILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(shell dirname $(THIS_FILE))

DOCKERFILES_DIR := $(THIS_DIR)/.tmp/layers
include $(THIS_DIR)/layer.mk

### BUILDER_IMAGE_LAYERS

# Each grouping below defines a layer of the builder image.
# Each definition includes:
#
#   1. The name of the image layer to build (each has a corresponding file in
#      build/<name>.Dockerfile) (required)
#   2. The name of the base image layer (defined in another grouping)
#      if this is left blank, then we just rely on the Dockerfile FROM line.
#   3. Source include: a list of files and directories to consider the source
#      for this layer. Keep this list minimal in order to benefit from caching.
#      Each layer includes own Dockerfile by default. (required)
#   4. Source exclude: a list of files and directories to exclude.
#      This filter is applied after source include, so you can e.g. include .
#      and then just filter our the stuff you do not want.

# The base image contains base dependencies like libraries and tools.
BASE_NAME           := base
BASE_BASEIMAGE      :=
BASE_SOURCE_INCLUDE :=
BASE_SOURCE_EXCLUDE := 
$(eval $(call LAYER,$(BASE_NAME),$(BASE_BASEIMAGE),$(BASE_SOURCE_INCLUDE),$(BASE_SOURCE_EXCLUDE)))

# The yarn image contains all the UI dependencies for the ui layer.
YARN_NAME           := yarn
YARN_BASEIMAGE      := base
YARN_SOURCE_INCLUDE := ui/yarn.lock ui/package.json
YARN_SOURCE_EXCLUDE :=
$(eval $(call LAYER,$(YARN_NAME),$(YARN_BASEIMAGE),$(YARN_SOURCE_INCLUDE),$(YARN_SOURCE_EXCLUDE)))

# The ui image contains the compiled ui code in ui/
UI_NAME           := ui
UI_BASEIMAGE      := yarn
UI_SOURCE_INCLUDE := ui/
UI_SOURCE_EXCLUDE :=
$(eval $(call LAYER,$(UI_NAME),$(UI_BASEIMAGE),$(UI_SOURCE_INCLUDE),$(UI_SOURCE_EXCLUDE)))

# The static image is the one we finally use for compilation of the source.
STATIC_NAME           := static
STATIC_BASEIMAGE      := ui
STATIC_SOURCE_INCLUDE := .
STATIC_SOURCE_EXCLUDE := release/ .circleci/
$(eval $(call LAYER,$(STATIC_NAME),$(STATIC_BASEIMAGE),$(STATIC_SOURCE_INCLUDE),$(STATIC_SOURCE_EXCLUDE)))

write-cache-keys: $(addsuffix -write-cache-key,$(LAYERS))
	@echo "==> All cache keys written."

.PHONY: debug
debug:
	@echo "base_SOURCE_COMMIT       = $(base_SOURCE_COMMIT)"
	@echo "base_SOURCE_ID           = $(base_SOURCE_ID)"
	@echo "base_SOURCE_GIT          = $(base_SOURCE_GIT)"
	@echo "yarn_SOURCE_COMMIT       = $(yarn_SOURCE_COMMIT)"
	@echo "yarn_SOURCE_ID           = $(yarn_SOURCE_ID)"
	@echo "yarn_SOURCE_GIT          = $(yarn_SOURCE_GIT)"
	@echo "ui_SOURCE_COMMIT         = $(ui_SOURCE_COMMIT)"
	@echo "ui_SOURCE_ID             = $(ui_SOURCE_ID)"
	@echo "ui_SOURCE_GIT            = $(ui_SOURCE_GIT)"
	@echo "static_SOURCE_COMMIT     = $(static_SOURCE_COMMIT)"
	@echo "static_SOURCE_ID         = $(static_SOURCE_ID)"
	@echo "static_SOURCE_GIT        = $(static_SOURCE_GIT)"

### BEGIN Pre-processing to ensure marker files aren't lying.

base_UPDATED   := $(strip $(shell $(call base_UPDATE_MARKER_FILE)))
yarn_UPDATED   := $(strip $(shell $(call yarn_UPDATE_MARKER_FILE)))
ui_UPDATED     := $(strip $(shell $(call ui_UPDATE_MARKER_FILE)))
static_UPDATED := $(strip $(shell $(call static_UPDATE_MARKER_FILE)))

ifneq ($(base_UPDATED),)
$(info $(base_UPDATED))
endif

ifneq ($(yarn_UPDATED),)
$(info $(yarn_UPDATED))
endif

ifneq ($(ui_UPDATED),)
$(info $(ui_UPDATED))
endif

ifneq ($(static_UPDATED),)
$(info $(static_UPDATED))
endif

### END pre-processing.

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
# terms of build tags or other build inputs. EDITION should always form part of the BUNDLE_NAME,
# and if non-empty MUST begin with a +.
EDITION ?=

### Calculated package parameters.

# BUNDLE_NAME is the name of the release bundle.
BUNDLE_NAME ?= $(PRODUCT_NAME)$(EDITION)
# PACKAGE_NAME is the unique name of a specific build of this product.
PACKAGE_NAME ?= $(BUNDLE_NAME)_$(PRODUCT_VERSION)_$(GOOS)_$(GOARCH)
PACKAGE_FILENAME ?= $(PACKAGE_NAME).zip
# PACKAGE is the zip file containing a specific binary.
PACKAGE = $(OUT_DIR)/$(PACKAGE_FILENAME)

### Calculated build inputs.

# LDFLAGS: These linker commands inject build metadata into the binary.
LDFLAGS += -X github.com/hashicorp/vault/sdk/version.GitCommit="$(static_SOURCE_ID)"
LDFLAGS += -X github.com/hashicorp/vault/sdk/version.Version="$(PRODUCT_VERSION_MMP)"
LDFLAGS += -X github.com/hashicorp/vault/sdk/version.VersionPrerelease="$(PRODUCT_VERSION_PRE)"

# OUT_DIR tells the Go toolchain where to place the binary.
OUT_DIR := $(PACKAGE_OUT_ROOT)/$(PACKAGE_NAME)/$(static_SOURCE_ID)

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
DOCKER_RUN_COMMAND = docker run $(DOCKER_RUN_FLAGS) $(static_IMAGE_NAME) $(DOCKER_SHELL) "$(BUILD_COMMAND) && $(ARCHIVE_COMMAND)"
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
	@if [ ! -f $(static_IMAGE) ]; then $(MAKE) -f $(THIS_FILE) $(static_IMAGE); fi
	@mkdir -p $$(dirname $@)
	@echo "==> Building package: $@"
	@rm -rf ./$(OUT_DIR)
	@mkdir -p ./$(OUT_DIR)
	@docker rm -f $(BUILD_CONTAINER_NAME) > /dev/null 2>&1 || true # Speculative cleanup.
	$(DOCKER_RUN_COMMAND)
	$(DOCKER_CP_COMMAND)
	@docker rm -f $(BUILD_CONTAINER_NAME) # Imperative cleanup.
