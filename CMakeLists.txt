cmake_minimum_required(VERSION 3.20)
project(OYDVAT)
include(CTest)

add_executable(OYDVAT oydvat.c)
add_test(NAME OYDVATTest COMMAND "C:\\Windows\\System32\\cmd.exe" test.bat)
