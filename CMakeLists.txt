cmake_minimum_required(VERSION 3.12)
project(NDSHW1 C)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES
        receiver.c
        sender.c
        gbn.c
        gbn.h
        )

add_executable(ReceiverServer receiver.c gbn.c)
add_executable(SenderClient sender.c gbn.c)
