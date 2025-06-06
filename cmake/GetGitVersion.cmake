# GetGitVersion.cmake
# - Returns a version string from Git tags
#
# This function inspects the annotated git tags for the project and returns a string
# into a CMake variable
#
#  get_git_version(<var> [WORKING_DIRECTORY <dir>])
#
# - Example
#
# include(GetGitVersion)
# get_git_version(GIT_VERSION WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

find_package(Git QUIET)

if(__get_git_version)
  return()
endif()
set(__get_git_version INCLUDED)

function(get_git_version var)
  # Parse arguments
  cmake_parse_arguments(GGV "" "WORKING_DIRECTORY" "" ${ARGN})
  
  # Use provided working directory or default to current source dir
  if(GGV_WORKING_DIRECTORY)
    set(WORK_DIR ${GGV_WORKING_DIRECTORY})
  else()
    set(WORK_DIR ${CMAKE_CURRENT_SOURCE_DIR})
  endif()
  
  if(GIT_EXECUTABLE)
    # Get the latest tag that matches semantic versioning
    execute_process(
      COMMAND ${GIT_EXECUTABLE} describe --match "v[0-9]*.[0-9]*.[0-9]*" --abbrev=8 --tags
      WORKING_DIRECTORY ${WORK_DIR}
      RESULT_VARIABLE status
      OUTPUT_VARIABLE GIT_VERSION
      ERROR_QUIET
    )
    
    if(${status})
      # If no tags found, try to get just any tag
      execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --abbrev=8 --tags
        WORKING_DIRECTORY ${WORK_DIR}
        RESULT_VARIABLE status2
        OUTPUT_VARIABLE GIT_VERSION
        ERROR_QUIET
      )
      
      if(${status2})
        # If still no tags, use default version with commit hash
        execute_process(
          COMMAND ${GIT_EXECUTABLE} rev-parse --short=8 HEAD
          WORKING_DIRECTORY ${WORK_DIR}
          RESULT_VARIABLE status3
          OUTPUT_VARIABLE GIT_COMMIT
          ERROR_QUIET
        )
        
        if(${status3})
          set(GIT_VERSION "v0.0.0")
        else()
          string(STRIP "${GIT_COMMIT}" GIT_COMMIT)
          set(GIT_VERSION "v0.0.0-${GIT_COMMIT}")
        endif()
      else()
        string(STRIP "${GIT_VERSION}" GIT_VERSION)
        # Clean up the version string
        string(REGEX REPLACE "-[0-9]+-g" "-" GIT_VERSION "${GIT_VERSION}")
      endif()
    else()
      string(STRIP "${GIT_VERSION}" GIT_VERSION)
      # Clean up the version string
      string(REGEX REPLACE "-[0-9]+-g" "-" GIT_VERSION "${GIT_VERSION}")
    endif()
    
    # Work out if the repository is dirty
    execute_process(
      COMMAND ${GIT_EXECUTABLE} update-index -q --refresh
      WORKING_DIRECTORY ${WORK_DIR}
      OUTPUT_QUIET
      ERROR_QUIET
    )
    
    execute_process(
      COMMAND ${GIT_EXECUTABLE} diff-index --name-only HEAD --
      WORKING_DIRECTORY ${WORK_DIR}
      OUTPUT_VARIABLE GIT_DIFF_INDEX
      ERROR_QUIET
    )
    
    string(COMPARE NOTEQUAL "${GIT_DIFF_INDEX}" "" GIT_DIRTY)
    if(${GIT_DIRTY})
      set(GIT_VERSION "${GIT_VERSION}-dirty")
    endif()
    
  else()
    # Git not found, use default version
    set(GIT_VERSION "v0.0.0")
  endif()
  
  message(STATUS "Git Version: ${GIT_VERSION}")
  set(${var} ${GIT_VERSION} PARENT_SCOPE)
endfunction()