cmake_minimum_required(VERSION 3.10)
project(ROS_AS)

set(CMAKE_CXX_STANDARD 11)
add_executable(ROS_AS main.cpp)
target_link_libraries(ROS_AS pthread stdc++fs Crypt)
