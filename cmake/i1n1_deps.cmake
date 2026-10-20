# SPDX-License-Identifier: GPL-2.0-only
#
# Resolves the sibling i1n1 repositories this repository builds against.
# Resolution order for each dependency (core, engine, platform, driverzone, host_efi):
#   1. already loaded in this CMake run (superbuild or an earlier i1n1_require call);
#   2. -DI1N1_<NAME>_SOURCE_DIR=<local checkout>;
#   3. FetchContent of the pinned repository URL and commit recorded below.
include_guard(GLOBAL)
include(FetchContent)


function(i1n1_require name)
  string(TOUPPER "${name}" _up)
  get_property(_loaded GLOBAL PROPERTY I1N1_REPO_${_up}_LOADED)
  if(_loaded)
    return()
  endif()
  if(I1N1_${_up}_SOURCE_DIR)
    add_subdirectory("${I1N1_${_up}_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/_i1n1/${name}")
    return()
  endif()
  if(NOT DEFINED _I1N1_REPO_URL_${name})
    message(FATAL_ERROR "i1n1_require: unknown repository '${name}'")
  endif()
  if(_I1N1_REPO_COMMIT_${name} STREQUAL "UNPINNED")
    message(FATAL_ERROR "i1n1 dependency '${name}' has no recorded commit. Configure with "
      "-DI1N1_${_up}_SOURCE_DIR=<path to a checkout of ${_I1N1_REPO_URL_${name}}>")
  endif()
  FetchContent_Declare(i1n1_${name}
    GIT_REPOSITORY "${_I1N1_REPO_URL_${name}}"
    GIT_TAG "${_I1N1_REPO_COMMIT_${name}}")
  FetchContent_MakeAvailable(i1n1_${name})
endfunction()
