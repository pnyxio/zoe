cmake_minimum_required(VERSION 3.10)
project(ed25519monero C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_library(ed25519monero STATIC
        crypto-ops-data.c
        crypto-ops.c
        crypto-ops.h
#        crypto-ops-added.h
#        generic-ops.h
        keccak.c
        keccak.h
)
