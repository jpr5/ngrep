## ngrep 1.48 (10.13.2025)

ngrep is like GNU grep applied to the network layer.  It's a PCAP-based tool
that allows you to specify an extended regular or hexadecimal expression to
match against data payloads of packets.  It understands many kinds of protocols,
including IPv4/6, TCP, UDP, ICMPv4/6, IGMP and Raw, across a wide variety of
interface types, and understands BPF filter logic in the same fashion as more
common packet sniffing tools, such as tcpdump and snoop.

## What's New

 * Upgrade to PCRE2
 * Add additional level of quiet for certain filtering scenarios
 * Update to latest autotools for ngrep and regex-0.12 (2.72, 2023)
 * Update manpage for missing options and typos
 * Fix BPF `DLT_` type detections within libpcap (e.g. `DLT_LINUX_SLL`)
 * Allow for specifying specific location of PCRE2 includes
 * Eliminate various non-fatal build warnings (e.g. `pcap_lookupdev` deprecation)
 * Fix `./configure --disable-tcpkill`
 * Source cleanup (nuke old files, unused vars, missing refs, etc)
 * Win32: -d allows device-name now (e.g. `\\Device\...`)
 * Win32: Removed `delay_socket` hack in favor of `Sleep()`

## How to use

ngrep was originally developed to:

* debug plaintext protocol interactions such as HTTP, IMAP, DNS, SIP, etc.
* identify and analyze anomalous network communications such as those between
  malware, zombies and viruses
* store, read and reprocess pcap dump files while looking for specific data
  patterns

As well, it could be used to do plaintext credential collection, as with HTTP
Basic Authentication, FTP or POP3 authentication.  Like all useful tools, it can
be used for good and for bad.

Visit [EXAMPLES](EXAMPLES.md) to learn more about how ngrep works and can be
leveraged to see all sorts of neat things.


## Support, Feedback, & Patches

If you need help, have constructive feedback, or would like to submit a patch,
please visit ngrep's project at GitHub and use the online tools there.  It will
help the author better manage the various requests and patches so that nothing
is lost or missed (as has been the case in the past, unfortunately).

* Issues: https://github.com/jpr5/ngrep/issues
* Patches: https://github.com/jpr5/ngrep/pulls


## Confirmed Working Platforms

* Linux 2.0+ (RH6+, SuSE, TurboLinux, Debian, Gentoo, Ubuntu, Mandrake, Slackware)/x86, RedHat/alpha Cobalt, (Qube2) Linux/MIPS
* Solaris 2.5.1, 2.6/SPARC, Solaris 7, Solaris 8/SPARC, Solaris 9/SPARC
* FreeBSD 2.2.5, 3.1, 3.2, 3.4-RC, 3.4-RELEASE, 4.0, 5.0
* OpenBSD 2.4 (after upgrading pcap from 0.2), 2.9, 3.0, 3.1+
* NetBSD 1.5/SPARC
* Digital Unix V4.0D (OSF/1), Tru64 5.0, Tru64 5.1A
* HPUX 11
* IRIX
* AIX 4.3.3.0/PowerPC
* BeOS R5
* Mac OS X 10+
* GNU HURD
* Windows 95, 98, NT, 2000, XP, 2003/x86, 7, 8, 8.1, 10


## Miscellany

Please see [CREDITS](CREDITS) for a partial list of the many people who helped make ngrep
what it is today.  Also, please note that ngrep is released under a simple
BSD-style license, though depending on which regex library you compile
against, you'll either get the GPL (GNU regex) or Artistic (PCRE).

 * Unix libpcap: http://www.tcpdump.org/release/
 * Windows libpcap: http://www.winpcap.org/install/
 * PCRE: http://www.pcre.org/
