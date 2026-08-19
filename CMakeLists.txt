cmake_minimum_required(VERSION 3.10)
project(TorrentFileSharing CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Homebrew's openssl is keg-only on macOS, so it isn't on the default
# search path. Point CMake at it unless the caller already set a hint.
if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR)
    execute_process(
        COMMAND brew --prefix openssl@3
        OUTPUT_VARIABLE HOMEBREW_OPENSSL_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(HOMEBREW_OPENSSL_PREFIX)
        set(OPENSSL_ROOT_DIR ${HOMEBREW_OPENSSL_PREFIX})
    endif()
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Opt-in sanitizer builds, e.g.: cmake -S . -B build-asan -DSANITIZE=address,undefined
if(SANITIZE)
    add_compile_options(-fsanitize=${SANITIZE} -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=${SANITIZE})
endif()

add_executable(tracker
    tracker/tracker.cpp
    tracker/trackersync.cpp
    common/tls.cpp
)
target_include_directories(tracker PRIVATE common)
target_link_libraries(tracker PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

add_executable(peer
    peer/peer.cpp
    peer/peerserver.cpp
    peer/peerdownload.cpp
    common/tls.cpp
)
target_include_directories(peer PRIVATE common)
target_link_libraries(peer PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

enable_testing()
add_test(
    NAME integration_test
    COMMAND sh ${CMAKE_SOURCE_DIR}/tests/integration_test.sh $<TARGET_FILE_DIR:tracker>
)
set_tests_properties(integration_test PROPERTIES TIMEOUT 60)
