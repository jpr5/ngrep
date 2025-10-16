## ngrep 1.48 (10.13.2025) [![Build](https://github.com/jpr5/ngrep/actions/workflows/build.yml/badge.svg)](https://github.com/jpr5/ngrep/actions/workflows/build.yml)


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
 * Win64: `-d` allows device-name now (e.g. `\\Device\...`)
 * Win64: Removed `delay_socket` hack in favor of `Sleep()`
 * Win64: Build with PCRE2 by default

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

## Working Platforms

ngrep was ported extensively to a multitude of platforms, but over time access to
them diminished.  The list below is the original list; for a current list of
confirmed working platforms, see our [autobuilds](https://github.com/jpr5/ngrep/actions/workflows/build.yml),
which includes the most popular OSes, compiler toolchains and cpu architectures.

* Linux 2.0+ (RH6+, SuSE, TurboLinux, Debian, Gentoo, Ubuntu, Mandrake, Slackware)/x86, RedHat/alpha, Cobalt (Qube2), Linux/MIPS
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

## Support, Feedback, & Patches

If you need help, have constructive feedback, or would like to submit a patch,
please visit ngrep's project at GitHub and use the online tools there.  It will
help the author better manage the various requests and patches so that nothing
is lost or missed (as has been the case in the past, unfortunately).

* Issues: https://github.com/jpr5/ngrep/issues
* Patches: https://github.com/jpr5/ngrep/pulls

Please see [CREDITS](CREDITS) for a partial list of the many people who helped make ngrep
what it is today.  Also, please note that ngrep is released under a simple
BSD-style license, though depending on which regex library you compile
against, you'll either get the GPL (GNU regex) or Artistic (PCRE).

## A Request to Distribution Package Maintainers

Over the decades (!), ngrep has been included de facto in many popular distributions,
several of which have dedicated package maintainers.  Many of them have helpfully
fielded issues reported by users of their distributions, and have even created patches
to ngrep -- but I am seldom made aware.  Every few years I have to hunt down what bug
reports and patches may exist, in often arcane vendor-specific tracking systems, so
that I can incorporate them for everyone's benefit.  And sometimes I don't find them
all.

If you are a package maintainer for an OS or distribution, and find yourself
fielding a bug report or writing a patch for ngrep, *please* at minimum CC me so
that I can track (and possibly solve) the issue.  Ideally, send me a link to a
patch or pull request so that I can review it and merge it in.

The way I see it, at the end of the day it's my code, so it's my responsibility, but
I can't be everywhere to see everything.  I need your help to do a good job.

Thank you, sincerely, for all that you have done, and all that you will do. 🙏
