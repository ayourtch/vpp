# Copyright (c) 2023 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# macOS Platform

darwin_arch = $(shell uname -m)

ifeq ($(darwin_arch),x86_64)
darwin_march = corei7
endif

ifeq ($(darwin_arch),arm64)
darwin_march = armv8-a
endif

darwin_native_tools = clang
darwin_toolchain = 
darwin_root_dir = /usr/local

darwin_cc = clang
darwin_cxx = clang++

darwin_march_flags = -march=$(darwin_march)
darwin_native_march_flags = $(darwin_march_flags)

darwin_clib = libc++
darwin_cflags = -fPIC
darwin_cxxflags = -fPIC

darwin_include_path = $(darwin_root_dir)/include
darwin_lib_path = $(darwin_root_dir)/lib

# No DPDK on macOS builds
darwin_uses_dpdk = no
darwin_uses_openssl = yes

darwin_defines = -DDISABLE_DPDK=1
darwin_defines += -DPNG_SETJMP_NOT_SUPPORTED=1
darwin_defines += -DMAC_PLATFORM=1

# Set platform specifics
platform = darwin

