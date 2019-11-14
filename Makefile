# Copyright 2019 Google, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

export GO111MODULE = on
export GOFLAGS = -mod=vendor

# build
build:
	@GOOS=linux GOARCH=amd64 go build \
	  -a \
		-ldflags "-s -w -extldflags 'static'"  \
		-installsuffix cgo \
		-tags netgo \
		-o build/oauth2l \
		./...
.PHONY: build

# deps updates all dependencies to their latest version and vendors the changes
deps:
	@go get -u -mod="" ./...
	@go mod tidy
	@go mod vendor
.PHONY: deps

# dev installs the tool locally
dev:
	@go install -i ./...
.PHONY: dev

# test runs the tests
test:
	@go test -parallel=40 -count=1 ./...
.PHONY: test
