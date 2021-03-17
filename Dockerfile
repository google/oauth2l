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

FROM golang:1.13 AS builder

ENV GO111MODULE=on \
  CGO_ENABLED=0 \
  GOOSES=linux \
  GOARCHES=amd64

WORKDIR /src
COPY . .

RUN make build


# This is intentionally alpine instead of distroless so users can mount this as
# part of a build step or run custom commands without needing to build their own
# container image.
FROM alpine:latest
RUN apk --no-cache add ca-certificates && \
  update-ca-certificates
RUN apk --no-cache add curl

COPY --from=builder /src/build/linux_amd64/oauth2l /bin/oauth2l
ENTRYPOINT ["/bin/oauth2l"]
