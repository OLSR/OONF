cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
if(POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif()

project (OONF C)

if (NOT OONF_NO_TESTING)
    ENABLE_TESTING()
endif (NOT OONF_NO_TESTING)

#####################################
#### set path to source for apps ####
#####################################

SET(APP_DATA_C_IN ${CMAKE_CURRENT_LIST_DIR}/src/main/app_data.c.in)
SET(MAIN_C ${CMAKE_CURRENT_LIST_DIR}/src/main/main.c)
SET(VERSION_CMAKE_IN ${CMAKE_CURRENT_LIST_DIR}/cmake/files/version.cmake.in)
SET(VERSION_SOURCE_DIR ${CMAKE_SOURCE_DIR})
SET(VERSION_SOURCE_SUB_DIR ${CMAKE_CURRENT_LIST_DIR})

#################################
#### add include directories ####
#################################

include_directories(${CMAKE_CURRENT_LIST_DIR}/include)
include_directories(${CMAKE_BINARY_DIR})

###########################
#### API configuration ####
###########################

# add define for length of base path
string(LENGTH "${CMAKE_SOURCE_DIR}/" BASELENGTH)
add_definitions(-DBASEPATH_LENGTH=${BASELENGTH})

# set cached variables
include (${CMAKE_CURRENT_LIST_DIR}/cmake/lib_config.cmake)

# include compiler flags
include (${CMAKE_CURRENT_LIST_DIR}/cmake/cc_flags.cmake)

# helper for test case creation
include (${CMAKE_CURRENT_LIST_DIR}/cmake/create_test.cmake)

########################################
#### get repository tag and version ####
########################################

include (${CMAKE_CURRENT_LIST_DIR}/cmake/get_version.cmake)
IF(EXISTS "${CMAKE_BINARY_DIR}/version.cmake")
  include (${CMAKE_BINARY_DIR}/version.cmake)
ENDIF()
