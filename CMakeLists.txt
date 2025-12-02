cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project (OONF C)

###########################
#### API configuration ####
###########################

# set cached variables
#include (./cmake/lib_config.cmake)

# include compiler flags
#include (./cmake/cc_flags.cmake)

# include global variables
include (./CMakeListsGlobal.cmake)

########################################################
#### Set a default build type if none was specified ####
########################################################

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to 'Debug' as none was specified.")
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo")
endif()

########################################
#### get repository tag and version ####
########################################

#include (cmake/get_version.cmake)
#IF(EXISTS "${PROJECT_BINARY_DIR}/version.cmake")
#  include (${PROJECT_BINARY_DIR}/version.cmake)
#ENDIF()

########################
#### Doxygen target ####
########################

find_package(Doxygen)
if(DOXYGEN_FOUND)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/files/framework.doxyfile.in
        ${CMAKE_CURRENT_BINARY_DIR}/framework.doxyfile @ONLY)
    add_custom_target(doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/framework.doxyfile
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
endif(DOXYGEN_FOUND)

#############################
#### add tarball targets ####
#############################

ADD_CUSTOM_TARGET(tar    COMMAND ${CMAKE_COMMAND}
                                 -D SOURCE:STRING=${CMAKE_SOURCE_DIR}
                                 -D BINARY:STRING=${PROJECT_BINARY_DIR}
                                 -D VERSION:STRING=${VERSION}
                                 -D FORMAT:STRING=tar
                                 -D TARBALL:STRING=${TARBALL}
                                 -D TARPREFIX:STRING=${TARPREFIX}
                                 -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/generate_archive.cmake)
ADD_CUSTOM_TARGET(targz  COMMAND ${CMAKE_COMMAND}
                                 -D SOURCE:STRING=${CMAKE_SOURCE_DIR}
                                 -D BINARY:STRING=${PROJECT_BINARY_DIR}
                                 -D VERSION:STRING=${VERSION}
                                 -D FORMAT:STRING=tar.gz
                                 -D TARBALL:STRING=${TARBALL}
                                 -D TARPREFIX:STRING=${TARPREFIX}
                                 -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/generate_archive.cmake)
ADD_CUSTOM_TARGET(tarbz2 COMMAND ${CMAKE_COMMAND}
                                 -D SOURCE:STRING=${CMAKE_SOURCE_DIR}
                                 -D BINARY:STRING=${PROJECT_BINARY_DIR}
                                 -D VERSION:STRING=${VERSION}
                                 -D FORMAT:STRING=tar.bz2
                                 -D TARBALL:STRING=${TARBALL}
                                 -D TARPREFIX:STRING=${TARPREFIX}
                                 -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/generate_archive.cmake)
ADD_CUSTOM_TARGET(zip    COMMAND ${CMAKE_COMMAND}
                                 -D SOURCE:STRING=${CMAKE_SOURCE_DIR}
                                 -D BINARY:STRING=${PROJECT_BINARY_DIR}
                                 -D VERSION:STRING=${VERSION}
                                 -D FORMAT:STRING=zip
                                 -D TARBALL:STRING=${TARBALL}
                                 -D TARPREFIX:STRING=${TARPREFIX}
                                 -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/generate_archive.cmake)

#########################
#### Compile targets ####
#########################

# include build helper
include (cmake/declare_library.cmake)

# define static and dynamic target
add_custom_target(static)
add_custom_target(dynamic)
add_custom_target(build_tests)

# start compiling core and plugins
add_subdirectory(src)
add_subdirectory(apps)
