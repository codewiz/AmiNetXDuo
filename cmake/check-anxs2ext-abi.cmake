# The anxs2ext.h callbacks take their arguments on the stack.
#
#   include(check-anxs2ext-abi)   -- at configure, m68k cross builds only
#
# RxDirect, RxFilled and TxFlags are called by a driver built separately from
# the library, often from another release, and every release before -mregparm
# pushed their arguments.  d6b6a7e7 left the typedefs unpinned: its library
# read a0/d0 for what a 144042c driver had pushed, RxDirect answered an address
# made of its own code bytes, and on a PiStorm32 A1200 neither card came up.
# This compiles a call through each typedef with the tree's flags and stops
# the configure unless the caller pops what it pushed: 8, 16 and 4 bytes.
# It also pins the record's offsets, which no version from MIN on may move.
#
# SPDX-License-Identifier: MIT

if(NOT CMAKE_CROSSCOMPILING)
    return()
endif()

set(_s2x_dir "${CMAKE_BINARY_DIR}/check-anxs2ext-abi")
file(MAKE_DIRECTORY "${_s2x_dir}")
file(WRITE "${_s2x_dir}/probe.c" [=[
#include <stddef.h>
#include <aminetxduo/anxs2ext.h>
/* The record's prefix is the same at every version from MIN on: a driver
   accepting [MIN, VERSION] reads these offsets whichever one it is handed. */
_Static_assert(offsetof(AnxdS2Extension, Version)  ==  0, "Version");
_Static_assert(offsetof(AnxdS2Extension, Size)     ==  2, "Size");
_Static_assert(offsetof(AnxdS2Extension, Request)  ==  4, "Request");
_Static_assert(offsetof(AnxdS2Extension, Accepted) ==  8, "Accepted");
_Static_assert(offsetof(AnxdS2Extension, RxDirect) == 12, "RxDirect");
_Static_assert(offsetof(AnxdS2Extension, RxFilled) == 16, "RxFilled");
_Static_assert(offsetof(AnxdS2Extension, TxFlags)  == 20, "TxFlags");
_Static_assert(sizeof(AnxdS2Extension)             == 24, "size");
UBYTE *probe_rx_direct(AnxdS2RxDirect f, APTR io, ULONG len)
{
    return f(io, len) + 1;
}
ULONG probe_rx_filled(AnxdS2RxFilled f, APTR io, ULONG len, ULONG sum, UBYTE fl)
{
    f(io, len, sum, fl);
    return len + 1;
}
UBYTE probe_tx_flags(AnxdS2TxFlags f, APTR io)
{
    return (UBYTE)(f(io) + 1);
}
]=])

# The flags the objects are built with, less LTO: -S has to produce assembly.
separate_arguments(_s2x_flags UNIX_COMMAND
    "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_RELEASE}")
list(REMOVE_ITEM _s2x_flags -flto)

execute_process(
    COMMAND "${CMAKE_C_COMPILER}" ${_s2x_flags}
            "-I${CMAKE_SOURCE_DIR}/include" -S
            -o "${_s2x_dir}/probe.s" "${_s2x_dir}/probe.c"
    RESULT_VARIABLE _s2x_rc
    ERROR_VARIABLE  _s2x_err)
if(NOT _s2x_rc EQUAL 0)
    message(FATAL_ERROR "check-anxs2ext-abi: the probe did not compile:\n${_s2x_err}")
endif()

file(READ "${_s2x_dir}/probe.s" _s2x_asm)

foreach(_s2x_pair "rx_direct;8" "rx_filled;16" "tx_flags;4")
    list(GET _s2x_pair 0 _s2x_fn)
    list(GET _s2x_pair 1 _s2x_n)
    string(REGEX MATCH "_probe_${_s2x_fn}:[^:]*" _s2x_body "${_s2x_asm}")
    if(NOT _s2x_body MATCHES
       "jsr[^\n]*\n(.*\n)?[ \t]*(addq\\.[wl][ \t]+#${_s2x_n},%?sp|add\\.[wl][ \t]+#${_s2x_n},%?sp|lea[ \t]+\\(${_s2x_n},%?sp\\),%?sp|lea[ \t]+${_s2x_n}\\(%?sp\\),%?sp|lea[ \t]+%?sp@\\(${_s2x_n}\\),%?sp)")
        message(FATAL_ERROR
            "check-anxs2ext-abi: a call through AnxdS2* (${_s2x_fn}) does not "
            "pass its arguments on the stack under -mregparm=${AMINETXDUO_REGPARM}; "
            "a driver from another build would read the wrong registers.  "
            "See ${_s2x_dir}/probe.s")
    endif()
endforeach()

message(STATUS "check-anxs2ext-abi: driver callbacks pass on the stack (regparm ${AMINETXDUO_REGPARM})")
