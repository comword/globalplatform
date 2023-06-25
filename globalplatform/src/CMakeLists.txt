SET(SOURCES rnConn.cpp stringify.c crypto.c loadfile.c util.c debug.c init.c globalplatform.c unzip/unzip.c unzip/ioapi.c)

include(GNUInstallDirs)
INCLUDE(CheckCCompilerFlag)
INCLUDE(CMakePushCheckState)

IF(DEBUG)
  SET(CMAKE_BUILD_TYPE "Debug")
  IF(MSVC_VERSION)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W4")
  ELSE()
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall")
  ENDIF()

  # check for fsanitize support
  CMAKE_PUSH_CHECK_STATE()
  SET(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
  check_c_compiler_flag("-fsanitize=address" FSANITIZE)
  CMAKE_POP_CHECK_STATE()
  IF(FSANITIZE)
  MESSAGE("fsanitize supported")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
  ENDIF()

  # check for Wpedantic support
  CMAKE_PUSH_CHECK_STATE()
  SET(CMAKE_REQUIRED_FLAGS "-Wpedantic")
  check_c_compiler_flag("-Wpedantic" PEDANTIC)
  CMAKE_POP_CHECK_STATE()
  IF(PEDANTIC)
  MESSAGE("pedantic supported")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wpedantic")
  ENDIF()

  # Enable debugging output
  ADD_DEFINITIONS(-DOPGP_DEBUG)

ELSE(DEBUG)
  SET(CMAKE_BUILD_TYPE "Release")
ENDIF(DEBUG)

ADD_LIBRARY(globalplatform SHARED ${SOURCES})

target_include_directories(globalplatform PRIVATE private-includes unzip)
target_include_directories(globalplatform
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/includes>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/pcsclite-includes>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

SET(LIBRARIES crypto ssl z)

TARGET_LINK_LIBRARIES(globalplatform ${LIBRARIES})
