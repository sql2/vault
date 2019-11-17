# build.mk
#
# build.mk builds the packages defined in packages.lock, first building all necessary
# builder images.
#
# NOTE: This file should always run as though it were in the repo root, so all paths
# are relative to the repo root.

# Include config.mk relative to this file (this allows us to invoke this file
# from different directories safely.
include $(shell dirname $(lastword $(MAKEFILE_LIST)))/config.mk

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

# Include the layers driver.
include $(RELEASE_DIR)/layer.mk

# Determine the SOURCE_ID for this package.
ifeq ($(ALLOW_DIRTY),YES)
DIRTY := $(shell git diff --exit-code $(GIT_REF) -- $(ALWAYS_EXCLUDE_SOURCE_GIT) > /dev/null 2>&1 || echo "dirty_")
PACKAGE_SOURCE_ID := $(DIRTY)$(shell git rev-parse $(GIT_REF))
else
PACKAGE_SOURCE_ID := $(shell git rev-parse $(GIT_REF))
endif

# PACKAGE_OUT_ROOT is the root directory where the final packages will be written to.
PACKAGE_OUT_ROOT ?= dist

VERSION_PATH := github.com/hashicorp/vault/vendor/github.com/hashicorp/vault/sdk/version

# LDFLAGS: These linker commands inject build metadata into the binary.
LDFLAGS += -X $(VERSION_PATH).GitCommit=$(PACKAGE_SOURCE_ID)
LDFLAGS += -X $(VERSION_PATH).Version=$(PRODUCT_VERSION_MMP)
LDFLAGS += -X $(VERSION_PATH).VersionPrerelease=$(PRODUCT_VERSION_PRE)

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
	-tags '$(BUILD_TAGS)' \
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
