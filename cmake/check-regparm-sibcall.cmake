# An indirect call whose callee takes a pointer first must load that pointer.
#
#   include(check-regparm-sibcall)   -- at configure, m68k cross builds only
#
# GCC 16.2.0b under -mregparm emits an indirect TAIL call as
# `move.l <target>,a0 / jmp (a0)': the call target lands in a0, which is the
# register the callee reads its first pointer argument from, and that argument
# is never loaded.  bsd_wait_sliced()'s `return call(arg, wait)' entered
# bsd_send_once() with its own address as `arg', so a->tcp was the callee's
# movem prologue (0x48E7....) and every NX_NO_WAIT send() hung.  The toolchain
# file passes -fno-optimize-sibling-calls with -mregparm; this compiles the
# same shape with the flags the tree builds with, and stops the configure if
# the call is still a jump, or at regparm 3 does not move `arg' (a2) to a0.
#
# SPDX-License-Identifier: MIT

if(NOT CMAKE_CROSSCOMPILING OR NOT AMINETXDUO_REGPARM GREATER 0)
    return()
endif()

set(_sib_dir "${CMAKE_BINARY_DIR}/check-regparm-sibcall")
file(MAKE_DIRECTORY "${_sib_dir}")
file(WRITE "${_sib_dir}/probe.c" [=[
typedef unsigned long ULONG;
typedef ULONG (*Call)(void *arg, ULONG wait);
extern ULONG other(void);
ULONG probe(void *base, ULONG wait, Call call, void *arg)
{
    (void)base;
    if (wait == 0)
        return call(arg, wait);
    other();
    return call(arg, wait) + 1;
}
]=])

# The flags the objects are built with, less LTO: -S has to produce assembly.
separate_arguments(_sib_flags UNIX_COMMAND
    "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_RELEASE}")
list(REMOVE_ITEM _sib_flags -flto)

execute_process(
    COMMAND "${CMAKE_C_COMPILER}" ${_sib_flags} -S
            -o "${_sib_dir}/probe.s" "${_sib_dir}/probe.c"
    RESULT_VARIABLE _sib_rc
    ERROR_VARIABLE  _sib_err)
if(NOT _sib_rc EQUAL 0)
    message(FATAL_ERROR "check-regparm-sibcall: the probe did not compile:\n${_sib_err}")
endif()

file(READ "${_sib_dir}/probe.s" _sib_asm)

if(_sib_asm MATCHES "jmp[ \t]+%?\\(")
    message(FATAL_ERROR
        "check-regparm-sibcall: an indirect call under -mregparm=${AMINETXDUO_REGPARM} "
        "is a tail jump, which loses the callee's first pointer argument; "
        "-fno-optimize-sibling-calls is missing from CMAKE_C_FLAGS.  "
        "See ${_sib_dir}/probe.s")
endif()

if(AMINETXDUO_REGPARM EQUAL 3 AND NOT _sib_asm MATCHES "move\\.l[ \t]+%?a2,%?a0")
    message(FATAL_ERROR
        "check-regparm-sibcall: the indirect call does not pass `arg' (a2) in a0 "
        "under -mregparm=3.  See ${_sib_dir}/probe.s")
endif()

message(STATUS "check-regparm-sibcall: indirect calls pass their pointer argument (regparm ${AMINETXDUO_REGPARM})")
