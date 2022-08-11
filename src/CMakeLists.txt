# SPDX-License-Identifier: MIT
#
# Copyright (c) 2022 The Authors.
# Authors: Wei Yue         <@w-yue>
#
# Summary: src level CMake listfile for Arion DP project

message("Processing src/CMakeList.txt")

include(extern/extern.cmake)
include(rpcgen/rpcgen.cmake)
include(cli/CMakeLists.txt)
include(dmn/CMakeLists.txt)

add_subdirectory(mgmt)
add_subdirectory(xdp)
