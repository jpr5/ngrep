/*
 * Win32-specific version for manual manipulation.
 */

/* PCRE2 support - will be defined by CMake if available */
#ifndef USE_PCRE2
#define USE_PCRE2                    0
#endif

#define USE_IPv6                     1
#define USE_VLAN_HACK                1

#define HAVE_DLT_RAW                 1
#define HAVE_DLT_LOOP                1
#define HAVE_DLT_LINUX_SLL           1
#define HAVE_DLT_IEEE802_11          1
#define HAVE_DLT_IEEE802_11_RADIO    1
#define HAVE_DLT_PFLOG               1
#define HAVE_DLT_PFSYNC              1
#define HAVE_DLT_IPNET               0

#define HAVE_DUMB_UDPHDR             0
#define HAVE_PCAP_FINDALLDEVS        1

#define USE_PCAP_RESTART             0
#define PCAP_RESTART_FUNC            0

#define USE_DROPPRIVS                0
#define DROPPRIVS_USER               "notused"

#define USE_TCPKILL                  0

/* Windows doesn't have these */
#define STDC_HEADERS                 1

