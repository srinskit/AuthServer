cmake_minimum_required(VERSION 3.10)
project(ROS_AS)

set(CMAKE_CXX_STANDARD 11)
set(CRYPT_LOC /usr/local/include/Crypt)
add_executable(ROS_AS main.cpp ${CRYPT_LOC}/Crypt.cpp ${CRYPT_LOC}/Crypt.h)
target_link_libraries(ROS_AS pthread stdc++fs mbedtls mbedcrypto mbedx509)
