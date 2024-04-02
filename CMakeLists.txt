cmake_minimum_required(VERSION 3.0.0)
project(crittografia VERSION 0.1.0 LANGUAGES C CXX)
add_subdirectory(json)
include(CTest)
enable_testing()

add_executable(Client Client.cpp Utility.cpp Utility.hpp)
add_executable(Server Server.cpp Utility.cpp Utility.hpp)
add_executable(User_account User_account.cpp Utility.cpp Utility.hpp)


find_package(OpenSSL REQUIRED)
target_link_libraries(Server nlohmann_json::nlohmann_json OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(Client nlohmann_json::nlohmann_json OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(User_account nlohmann_json::nlohmann_json OpenSSL::SSL OpenSSL::Crypto)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)