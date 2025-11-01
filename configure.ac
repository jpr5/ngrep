dnl
dnl Copyright (c) 2025  Jordan Ritter <jpr5@darkridge.com>
dnl
dnl Please refer to the LICENSE file for more information.
dnl
dnl NOTE: configure.in requires autoconf 2.57 or more recent.

AC_INIT([ngrep],m4_esyscmd_s([cat VERSION]),[jpr5@darkridge.com])
AC_CONFIG_SRCDIR([ngrep.c])

AC_DEFINE_UNQUOTED(VERSION, "AC_PACKAGE_VERSION", [ngrep version])

AC_MSG_RESULT
AC_MSG_RESULT(Configuring System ...)
AC_MSG_RESULT

AC_CANONICAL_TARGET
AC_PROG_CC

dnl Find strip or use a no-op for systems without it
AC_CHECK_TOOL(STRIP, strip, :)

AC_PREFIX_DEFAULT(/usr/local)
AS_IF([test -n "$(command -v tcpdump 2> /dev/null)"], [
   AC_PREFIX_PROGRAM(tcpdump)
])

EXTRA_DEFINES=""
EXTRA_INCLUDES=""
EXTRA_LDFLAGS=""
EXTRA_OBJS=""
EXTRA_LIBS=""

dnl
dnl Define the arguments that we accept.  Parse them first.
dnl

dnl
dnl Allow user to specify alternate ``nobody'' user.
dnl

AC_ARG_WITH([dropprivs-user], [
AS_HELP_STRING([--with-dropprivs-user[=user]], [use different user for dropprivs])],
[
  DROPPRIVS_USER="$withval"
],
[
  DROPPRIVS_USER="nobody"
])

dnl
dnl Enable or disable the drop privileges logic.
dnl

AC_ARG_ENABLE([dropprivs], [
AS_HELP_STRING([--disable-dropprivs], [disable privilege dropping logic])],
[
  use_dropprivs="$enableval"
],
[
  use_dropprivs="yes"
])

AS_IF([test $use_dropprivs = yes], [
   USE_DROPPRIVS="1"
], [
   USE_DROPPRIVS="0"
])

dnl
dnl IPv6 (and ICMPv6) support
dnl

AC_ARG_ENABLE([ipv6], [
AS_HELP_STRING([--enable-ipv6], [enable IPv6 (and ICMPv6) support])],
[
  use_ipv6="$enableval"
],
[
  use_ipv6="no"
])

AS_IF([test $use_ipv6 = yes], [
   USE_IPv6="1"
], [
   USE_IPv6="0"
])

dnl
dnl PCAP BPF filter expression lexer bugfix
dnl
dnl Typically ngrep is invoked with a (optional) search string plus a BPF
dnl filter. However, ngrep doesn't semantically understand BPF filter terms
dnl itself, so it assumes the first non-option parameter is the search string,
dnl and attempts to compile the remainder as the BPF filter expression. If the
dnl compilation fails, it probably means that no search string was specified, so
dnl it restarts the BPF filter expression lexer and attempts to compile the
dnl entire non-option parameter string as the expression. If that fails, then
dnl the specified BPF filter expression is definitely bogus and ngrep errors
dnl out.
dnl
dnl I favored this approach because it made invocation simpler & more fluid. In
dnl order to make it work however, I had to solve for a bug in older versions of
dnl libpcap where the library would segfault if the BPF filter compilation
dnl function was invoked more than once. The workaround turned out to be a
dnl simple invocation of the lexer's restart function in between compilation
dnl invocations, however that function wasn't normally exposed in the header
dnl since it was an internal built-in of whatever grammar lexer libpcap had
dnl compiled with (bison/yacc/etc).
dnl
dnl The default behavior has long been to restart the lexer (keeping invocation
dnl simpler) and provide a compile-time option to disable the mechanism, if
dnl anyone cared to.  Based on a more recent bug report however[1], it seems
dnl that the newer libpcap breaks when the lexer restart function is called.
dnl So, given the choice between old platforms working by default (always call
dnl restart/allow disablement at compile-time) vs. newer platforms working by
dnl default (never call restart/allow enablement at compile-time), the default
dnl behavior now is to do the latter.
dnl
dnl For versions of libpcap that require restart function invocation in between
dnl multiple lexer passes, allow them to enable it here.
dnl
dnl [1] https://github.com/jpr5/ngrep/issues/2
dnl

AC_ARG_ENABLE([pcap-restart], [
AS_HELP_STRING([--enable-pcap-restart], [enable BPF lexer restart bugfix for older versions of PCAP (default off)])],
[
  use_pcap_restart="$enableval"
],
[
  use_pcap_restart="no"
])

AS_IF([test $use_pcap_restart = yes], [
    USE_PCAP_RESTART="1"
], [
    USE_PCAP_RESTART="0"
])


dnl
dnl Configure the regular expression library.
dnl

REGEX_DIR=''
REGEX_OBJS=''

AC_ARG_ENABLE([pcre2], [
AS_HELP_STRING([--enable-pcre2], [use PCRE2 instead of GNU regex (default GNU)])],
[ use_pcre2="$enableval" ],
[ use_pcre2="no" ])

AS_IF([test $use_pcre2 = yes], [
  USE_PCRE2="1"
  EXTRA_INCLUDES="$EXTRA_INCLUDES $(pcre2-config --cflags-posix)"
  EXTRA_LIBS="$EXTRA_LIBS $(pcre2-config --libs-posix)"
], [
  USE_PCRE2="0"

  AC_MSG_RESULT
  AC_MSG_RESULT(Configuring GNU Regular Expression library ...)
  AC_MSG_RESULT

  REGEX_DIR='regex-0.12'
  REGEX_OBJS="$REGEX_DIR/regex.o"

  ( cd $REGEX_DIR && ./configure )

  EXTRA_INCLUDES="$EXTRA_INCLUDES -I$REGEX_DIR"
])

AC_SUBST(REGEX_DIR)
AC_SUBST(REGEX_OBJS)

dnl
dnl tcpkill/libnet support (from Debian patch)
dnl

AC_ARG_ENABLE([tcpkill], [
AS_HELP_STRING([--enable-tcpkill], [enable connection killing support (default off)])],
[
  use_tcpkill="$enableval"
],
[ use_tcpkill="no" ])

AC_ARG_ENABLE([vlan-hack], [
AS_HELP_STRING([--disable-vlan-hack], [disable automatic inclusion of VLAN frames (default on)])],
[use_vlan_hack="$enableval"],
[use_vlan_hack="yes"])

AS_IF([test $use_vlan_hack = yes], [
  USE_VLAN_HACK="1"
], [
  USE_VLAN_HACK="0"
])


AC_ARG_WITH([pcap-includes], [
AS_HELP_STRING([--with-pcap-includes=dir], [specify the pcap include directory])],
[PCAP_DIR=$withval],
[
  PCAP_DIR="`eval echo -n ${includedir}` \
            /usr/include /usr/include/pcap \
            /usr/local/include /usr/local/include/pcap \
            /opt/local/include /opt/local/include/pcap \
            /usr/share/include /usr/share/include/pcap \
            /opt/homebrew/Cellar/libpcap/*/include"
])

AC_ARG_WITH([pcre2-includes],[
AS_HELP_STRING([--with-pcre2-includes=dir], [specify the pcre2 include directory])
],[
    PCRE2_DIR=$withval
    EXTRA_INCLUDES="$EXTRA_INCLUDES -I$PCRE2_DIR"
    DIR="$PCRE2_DIR/lib"
    AS_IF([test -d $DIR], [
        EXTRA_LDFLAGS="$EXTRA_LDFLAGS -L$DIR"
    ])
],
[])

AC_MSG_RESULT
AC_MSG_RESULT(Configuring Network Grep ...)
AC_MSG_RESULT

dnl
dnl OS-specific options
dnl

BASE_PCAP_H="pcap/pcap.h"

AS_CASE(["$target_os"],
[*linux*], [
    AC_SUBST(OS, LINUX)

    EXTRA_DEFINES="$EXTRA_DEFINES -D_DEFAULT_SOURCE=1"
],
[*openbsd*], [
    AC_SUBST(OS, BSD)

dnl OpenBSD doesn't have an indirect pcap.h, pointing to pcap/pcap.h.
dnl I guess it's just considered a core/built-in, as there isn't even a libpcap
dnl package to install (unlike *any* other OS or distribution).
    BASE_PCAP_H="pcap.h"
    EXTRA_DEFINES="$EXTRA_DEFINES -D_BSD_SOURCE=1"
],
[*bsd*], [
    AC_SUBST(OS, BSD)

    EXTRA_DEFINES="$EXTRA_DEFINES -D_BSD_SOURCE=1"
],
[*solaris*], [
    AC_SUBST(OS, SOLARIS)

    AC_CHECK_LIB(socket, socket,,
                 [AC_MSG_ERROR(no socket in -lsocket)])
    AC_CHECK_LIB(nsl, gethostbyname,,
                 [AC_MSG_ERROR(no gethostbyname in -lnsl)])

    EXTRA_DEFINES="$EXTRA_DEFINES -D_BSD_SOURCE=1"
    EXTRA_LIBS="$EXTRA_LIBS -lnsl -lsocket"
],
[*osf*], [
    AC_SUBST(OS, OSF1)

    EXTRA_DEFINES="$EXTRA_DEFINES -D_BSD_SOURCE=1 -D__STDC__=2"
],
[*hpux11*], [
    AC_SUBST(OS, BSD)

    EXTRA_DEFINES="$EXTRA_DEFINES -D_BSD_SOURCE=1"
],
[*aix*], [
    AC_SUBST(OS, AIX)

    EXTRA_DEFINES="$EXTRA_DEFINES -D_BSD_SOURCE=1"
],
[*darwin*], [
    AC_SUBST(OS, MACOSX)
], [
    AC_SUBST(OS, UNKNOWN_OS)
    AC_MSG_WARN(
Your OS ($target_os) is not supported yet.
Try playing with the build host and target options.
)
    sleep 3
])

EXTRA_DEFINES="$EXTRA_DEFINES -D__FAVOR_BSD=1"

dnl
dnl Quick Background:
dnl
dnl A long time ago, the libpcap team decided to change the functionality split
dnl and installation location of their header files.  Consequently, installing
dnl the prior version's headers, followed by the newer version's, would result
dnl in two sets of different but similarly-named headers.  This broke a lot of
dnl packages, since most developers just included <pcap.h> in their programs.
dnl Many (including ngrep) addressed the problem by detecting this condition and
dnl alerting the user to fix it manually.  Eventually the libpcap team decided
dnl to add back in the top-level pcap.h, presumably to rectify the hassle.
dnl
dnl On modern Linux distros, checking for this condition likely doesn't matter
dnl anymore.  However, ngrep targets a much broader range of (older) OSes, so
dnl it's still a possibility.  The re-addition of a top-level pcap.h confounds
dnl the old header presence check, so I've updated it to search for the version,
dnl PCAP_VERSION_MAJOR.  Maybe I'll delete it in another 5 years.  ;-)
dnl

dnl Ensure CPP and EGREP are set before the loop to avoid repeated checks
AC_PROG_CPP
AC_PROG_EGREP
AC_EGREP_CPP

AC_MSG_CHECKING(for a complete set of pcap headers)

pcap_base=""
for dir in $PCAP_DIR ; do
dnl In every case *BUT* OpenBSD, there's a indirect $include/pcap.h that
dnl points to $include/pcap/pcap.h.  For OpenBSD, there's no indirect; it's
dnl just $include/pcap.h.
    AS_IF([test -d $dir -a -r "$dir/$BASE_PCAP_H"], [
        AC_EGREP_CPP([yes], [
            #include "$dir/$BASE_PCAP_H"
            #ifdef PCAP_VERSION_MAJOR
            yes
            #endif
        ], [found=$dir], [found=""])

        AS_IF([test -n "$found" -a -n "$pcap_base" -a "$found" != "$pcap_base"], [
            AC_MSG_RESULT
            AC_MSG_RESULT
            AC_MSG_RESULT(more than one set found in:)
            AC_MSG_RESULT(  $pcap_base)
            AC_MSG_RESULT(  $found)
            AC_MSG_RESULT
            AC_MSG_ERROR(please wipe out all unused pcap installations)
        ], [
            pcap_base="$found"
        ])
    ])
done

AS_IF([test -z "$pcap_base"], [
    AC_MSG_RESULT(no)
    AC_MSG_ERROR(could not find a complete set of pcap headers)
], [
    AC_MSG_RESULT(found $pcap_base)

    dnl Cannot allow /usr/include, screws up cross-compiling

    AS_IF([test "$pcap_base" != "/usr/include"],[
        EXTRA_INCLUDES="$EXTRA_INCLUDES -I$pcap_base"

        dnl Best-effort; newer ld warns on missing dirs.
        DIR="`dirname $pcap_base`/lib"
        AS_IF([test -d $DIR], [
            EXTRA_LDFLAGS="$EXTRA_LDFLAGS -L$DIR"
        ])
    ])
])

dnl
dnl If tcpkill is enabled, check for libnet.
dnl

AS_IF([test $use_tcpkill = yes], [
    USE_TCPKILL="1"

dnl Find libnet-config with any suffix (e.g., libnet-config-1.1 on OpenBSD)
    AC_PATH_PROGS(LIBNET_CONFIG_BIN, [libnet-config libnet-config-1.1 libnet-config-1.0], [no])
    AS_IF([test $LIBNET_CONFIG_BIN = no], [
        AC_MSG_ERROR(!!! error: tcpkill feature enabled but libnet-config not found)
    ])

    EXTRA_OBJS="$EXTRA_OBJS tcpkill.o"
    EXTRA_DEFINES="$EXTRA_DEFINES $($LIBNET_CONFIG_BIN --defines)"
    EXTRA_INCLUDES="$EXTRA_INCLUDES $($LIBNET_CONFIG_BIN --cflags)"
    EXTRA_LIBS="$EXTRA_LIBS $($LIBNET_CONFIG_BIN --libs)"

    SAVE_LIBS="$LIBS"
    LIBS="$LIBS $EXTRA_LIBS"
    AC_CHECK_LIB(net, libnet_init,,echo !!! error: tcpkill feature enabled but no libnet found; exit)
    LIBS="$SAVE_LIBS"
], [
    USE_TCPKILL="0"
])

dnl
dnl Check for a working PCAP library we can link against..
dnl

AC_CHECK_LIB(pcap, pcap_open_live,,[AC_MSG_ERROR(a viable pcap lib is required)])

AC_CHECK_LIB(pcap, pcap_findalldevs,
[
    HAVE_PCAP_FINDALLDEVS="1"
],
[
    HAVE_PCAP_FINDALLDEVS="0"
]
)

dnl
dnl And the PCAP restart function.
dnl

AS_IF([test "$USE_PCAP_RESTART" = "1"], [
    PCAP_RESTART_FUNC="unused"

    for func in pcap_restart pcap_yyrestart yyrestart; do
        AC_CHECK_LIB(pcap, $func, found="$func")
        AS_IF([test -n "$found"], [
            USE_PCAP_RESTART="1"
            PCAP_RESTART_FUNC="$found"
            break
        ])
    done

    AS_IF([test "$PCAP_RESTART_FUNC" = "unused"], [
        AC_MSG_ERROR(BPF lexer restart fix requested, but no restart function found)
    ])
])

dnl
dnl Check for wcwidth() for UTF-8 character width calculation
dnl
AC_CHECK_FUNCS([wcwidth], [
    HAVE_WCWIDTH="1"
], [
    HAVE_WCWIDTH="0"
    AC_MSG_WARN([wcwidth() not found - will use bundled implementation])
])

dnl
dnl Next figure out which bpf header file to look at.
dnl

PCAP_H="$pcap_base/$BASE_PCAP_H"
AC_MSG_CHECKING(for BPF include path in $PCAP_H)
dnl Use sed instead of grep -o for Solaris compatibility
dnl All the @'s escape m4-sensitive characters
BPF=`sed -n 's/.*<\(@<:@^>@:>@*bpf\.h\)>.*/\1/p' $PCAP_H | head -1 | tr -d '\n'`
AS_IF([test -z "$BPF"], [
    AC_MSG_RESULT(not found)
    AC_MSG_ERROR(could not find where the BPF types are located)
], [
    AC_MSG_RESULT($BPF)
])

dnl
dnl Check for DLT_* types that might not have existed in older
dnl libpcap's
dnl

present=""
AC_MSG_CHECKING(for DLT_LINUX_SLL in $BPF)
AC_EGREP_CPP(yes,
[
#include <$BPF>
#ifdef DLT_LINUX_SLL
yes
#endif
],
[HAVE_DLT_LINUX_SLL="1" && AC_MSG_RESULT(yes)], [HAVE_DLT_LINUX_SLL="0" && AC_MSG_RESULT(no)])

present=""
AC_MSG_CHECKING(for DLT_LOOP in $BPF)
AC_EGREP_CPP(yes,
[
#include <$BPF>
#ifdef DLT_LOOP
yes
#endif
],
[HAVE_DLT_LOOP="1" && AC_MSG_RESULT(yes)], [HAVE_DLT_LOOP="0" && AC_MSG_RESULT(no)])

present=""
AC_MSG_CHECKING(for DLT_IEEE802_11 in $BPF)
AC_EGREP_CPP(yes,
[
#include <$BPF>
#ifdef DLT_IEEE802_11
yes
#endif
],
[HAVE_DLT_IEEE802_11="1" && AC_MSG_RESULT(yes)], [HAVE_DLT_IEEE802_11="0" && AC_MSG_RESULT(no)])


present=""
AC_MSG_CHECKING(for DLT_IEEE802_11_RADIO in $BPF)
AC_EGREP_CPP(yes,
[
#include <$BPF>
#ifdef DLT_IEEE802_11_RADIO
yes
#endif
],
[HAVE_DLT_IEEE802_11_RADIO="1" && AC_MSG_RESULT(yes)], [HAVE_DLT_IEEE802_11_RADIO="0" && AC_MSG_RESULT(no)])


present=""
AC_MSG_CHECKING(for DLT_RAW in $BPF)
AC_EGREP_CPP(yes,
[
#include <$BPF>
#ifdef DLT_RAW
yes
#endif
],
[HAVE_DLT_RAW="1" && AC_MSG_RESULT(yes)], [HAVE_DLT_RAW="0" && AC_MSG_RESULT(no)])


present=""
AC_MSG_CHECKING(for DLT_PFLOG in $BPF)
AC_EGREP_CPP(yes,
[
#include <$BPF>
#ifdef DLT_PFLOG
yes
#endif
],
[HAVE_DLT_PFLOG="1" && AC_MSG_RESULT(yes)], [HAVE_DLT_PFLOG="0" && AC_MSG_RESULT(no)])


present=""
AC_MSG_CHECKING(for DLT_IPNET in $BPF)
AC_EGREP_CPP(yes,
[
#include <$BPF>
#ifdef DLT_IPNET
yes
#endif
],
[HAVE_DLT_IPNET="1" && AC_MSG_RESULT(yes)], [HAVE_DLT_IPNET="0" && AC_MSG_RESULT(no)])


dnl
dnl Now that we're past the OS-specific stuff, which could have
dnl modified our USE_* and other defines, define them all now.
dnl

AC_DEFINE_UNQUOTED(USE_PCAP_RESTART,          $USE_PCAP_RESTART,          [whether to call the BPF lexer restart function between multiple BPF filter compilation attempts (default no)])
AC_DEFINE_UNQUOTED(PCAP_RESTART_FUNC,         $PCAP_RESTART_FUNC,         [routine used for restarting the BPF lexer])
AC_DEFINE_UNQUOTED(HAVE_PCAP_FINDALLDEVS,     $HAVE_PCAP_FINDALLDEVS,     [whether libpcap has `pcap_findalldevs' function])

AC_DEFINE_UNQUOTED(USE_PCRE2,                 $USE_PCRE2,                 [whether to use PCRE2 (default GNU Regex)])
AC_DEFINE_UNQUOTED(USE_IPv6,                  $USE_IPv6,                  [whether to use IPv6 (default off)])
AC_DEFINE_UNQUOTED(USE_TCPKILL,               $USE_TCPKILL,               [whether to enable tcpkill functionality (default off)])
AC_DEFINE_UNQUOTED(USE_VLAN_HACK,             $USE_VLAN_HACK,             [whether to automatically include VLAN frames (default on)])

AC_DEFINE_UNQUOTED(USE_DROPPRIVS,             $USE_DROPPRIVS,             [whether to use privileges dropping (default yes)])
AC_DEFINE_UNQUOTED(DROPPRIVS_USER,           "$DROPPRIVS_USER",           [pseudo-user for running ngrep (default "nobody")])

AC_DEFINE_UNQUOTED(HAVE_DLT_RAW,              $HAVE_DLT_RAW,              [presence of DLT_RAW in bpf.h])
AC_DEFINE_UNQUOTED(HAVE_DLT_PFLOG,            $HAVE_DLT_PFLOG,            [presence of DLT_PFLOG in $BPF])
AC_DEFINE_UNQUOTED(HAVE_DLT_IEEE802_11,       $HAVE_DLT_IEEE802_11,       [presence of DLT_IEEE802_11 in bpf.h])
AC_DEFINE_UNQUOTED(HAVE_DLT_IEEE802_11_RADIO, $HAVE_DLT_IEEE802_11_RADIO, [presence of DLT_IEEE802_11_RADIO in bpf.h])
AC_DEFINE_UNQUOTED(HAVE_DLT_LOOP,             $HAVE_DLT_LOOP,             [presence of DLT_LOOP in bpf.h])
AC_DEFINE_UNQUOTED(HAVE_DLT_LINUX_SLL,        $HAVE_DLT_LINUX_SLL,        [presence of DLT_LINUX_SLL in bpf.h])
AC_DEFINE_UNQUOTED(HAVE_DLT_IPNET,            $HAVE_DLT_IPNET,            [presence of DLT_IPNET in bpf.h])

dnl
dnl Merge our global tack-ons with autoconf's.
dnl

AC_SUBST(EXTRA_DEFINES)
AC_SUBST(EXTRA_INCLUDES)
AC_SUBST(EXTRA_LDFLAGS)
AC_SUBST(EXTRA_OBJS)
AC_SUBST(EXTRA_LIBS)

dnl
dnl Emit configuration messages about any flags specified.
dnl

AC_MSG_RESULT

AS_IF([test "$USE_PCAP_RESTART" = "1"], [
    AC_MSG_RESULT([CONFIG: BPF filter lexer restart enabled (using $PCAP_RESTART_FUNC)])
])

AS_IF([test "$USE_IPv6" = "1"], [
    AC_MSG_RESULT(CONFIG: IPv6 support enabled)
], [
    AC_MSG_RESULT(CONFIG: IPv6 support disabled)
])

AS_IF([test "$USE_DROPPRIVS" = "1"], [
    AC_MSG_RESULT([CONFIG: privilege dropping enabled (using $DROPPRIVS_USER)])
], [
    AC_MSG_RESULT(CONFIG: privilege dropping DISABLED)
])

AS_IF([test "$USE_PCRE2" = "1"], [
    AC_MSG_RESULT(CONFIG: using PCRE2 regex library)
], [
    AC_MSG_RESULT(CONFIG: using GNU regex library)
])

AS_IF([test "$USE_TCPKILL" = "1"], [
    AC_MSG_RESULT(CONFIG: tcpkill feature enabled)
], [
    AC_MSG_RESULT(CONFIG: tcpkill feature disabled)
])

AS_IF([test "$USE_VLAN_HACK" = "1"], [
    AC_MSG_RESULT(CONFIG: automatically including VLAN frames)
], [
    AC_MSG_RESULT(CONFIG: NOT automatically including VLAN frames)
])

dnl
dnl And we're done.  ALL YOUR BASE.  Don't forget.
dnl

AC_MSG_RESULT

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)
AC_OUTPUT
