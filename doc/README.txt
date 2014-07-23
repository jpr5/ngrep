Program: ngrep
Author: Jordan Ritter <jpr5@darkridge.com>
Version: 1.46.1 (7.23.2014)


Goal:

  A program that mimicks as much functionality in GNU grep as possible, applied
  at the network layer.


Description:

  ngrep strives to provide most of GNU grep's common features, applying them to
  the network layer.  ngrep is a pcap-aware tool that will allow you to specify
  extended regular or hexadecimal expressions to match against data payloads of
  packets.  It currently recognizes IPv4/6, TCP, UDP, ICMPv4/6, IGMP and Raw
  across Ethernet, PPP, SLIP, FDDI, Token Ring and null interfaces, and
  understands BPF filter logic in the same fashion as more common packet
  sniffing tools, such as tcpdump and snoop.


usage: ngrep <-hNXViwqpevxlDtTRM> <-IO pcap_dump> <-n num> <-d dev> <-A num>
             <-s snaplen> <-S limitlen> <-W normal|byline|single|none> <-c cols>
             <-P char> <-F file>
             <match expression> <bpf filter>

usage: ngrep <-hNXViwqpevxlDtTRM> <-IO pcap_dump> <-n num> <-d dev> <-A num>
             <-s snaplen> <-S limitlen> <-W normal|byline|single|none> <-c cols>
             <-P char> <-F file>
             <match expression> <bpf filter>
   -h  is help/usage
   -V  is version information
   -q  is be quiet (don't print packet reception hash marks)
   -e  is show empty packets
   -i  is ignore case
   -v  is invert match
   -R  is don't do privilege revocation logic
   -x  is print in alternate hexdump format
   -X  is interpret match expression as hexadecimal
   -w  is word-regex (expression must match as a word)
   -p  is don't go into promiscuous mode
   -l  is make stdout line buffered
   -D  is replay pcap_dumps with their recorded time intervals
   -t  is print timestamp every time a packet is matched
   -T  is print delta timestamp every time a packet is matched
         specify twice for delta from first match
   -M  is don't do multi-line match (do single-line match instead)
   -I  is read packet stream from pcap format file pcap_dump
   -O  is dump matched packets in pcap format to pcap_dump
   -n  is look at only num packets
   -A  is dump num packets after a match
   -s  is set the bpf caplen
   -S  is set the limitlen on matched packets
   -W  is set the dump format (normal, byline, single, none)
   -c  is force the column width to the specified size
   -P  is set the non-printable display char to what is specified
   -F  is read the bpf filter from the specified file
   -N  is show sub protocol number

On UNIX:
   -d  is use specified device instead of the pcap default

On Win32:
   -d  is use specified device (index) instead of the pcap default
   -L  is show the winpcap device list index


Tips:

  o When the intention is to match all packets (i.e. blank regex), it is
    technically faster to use an empty regex (``'') than to use ``.*'' or ``*''.

  o When sniffing interfaces that are very busy or are seeing large amounts of
    packet traffic, make sure to craft a BPF filter to limit what PCAP has to
    deliver to ngrep.  The ngrep parser takes a certain amount of time and while
    negligible on a slow interface, it can add up very quickly on a busy one.

  o Hexadecimal expressions can be in straight numeric form, 'DEADBEEF', or in
    symbolic form, '0xDEADBEEF'.  A byte is the smallest unit of measure you can
    match against.

  o As of v1.28, ngrep doesn't require a match expression.  However, there are
    cases where ngrep can be confused and think part of your bpf filter is the
    match expression, as in:

  % ngrep not port 80
  interface: eth0 (192.168.1.0/255.255.255.0)
  filter: ip and ( port 80 )
  match: not

    In cases like this, you will need to specify a blank match expression:

  % ngrep '' not port 80
  interface: eth0 (192.168.1.0/255.255.255.0)
  filter: ip and ( not port 80 )


  Please see http://ngrep.sourceforge.net/usage.html for more detailed examples
  describing ngrep usage.


Miscellany:

  Please see the ``doc/CREDITS.txt'' file for a listing of the people who helped
  make ngrep what it is today.  Also, please note that ngrep is released under a
  BSD-style license, though it currently relies upon the GNU regex library,
  which is protected under the GPL.

  Also, it is _highly recommended_ that you upgrade to the latest version of
  libpcap.  All versions 0.5 and more recent fix really annoying and in some
  cases fatal problems with the packet capture library.  If you happen to be
  using Windows, please check the WinPcap site to see if there are any updates.


Useful sites:

  o Unix libpcap:

      http://www.tcpdump.org/release/

  o Windows libpcap:

      http://www.winpcap.org/install/


Known Working Platforms:

  o Linux 2.0 - 3.14
     (RH6+, SuSE, TurboLinux, Debian, Gentoo, Ubuntu, Mandrake, Slackware)/x86
     RedHat/alpha
     Cobalt (Qube2) Linux/MIPS
  o Solaris 2.5.1, 2.6/SPARC, Solaris 7, Solaris 8/SPARC, Solaris 9/SPARC
  o FreeBSD 2.2.5, 3.1, 3.2, 3.4-RC, 3.4-RELEASE, 4.0, 5.0
  o OpenBSD 2.4 (after upgrading pcap from 0.2), 2.9, 3.0, 3.1
  o NetBSD 1.5/SPARC
  o Digital Unix V4.0D (OSF/1), Tru64 5.0, Tru64 5.1A
  o HPUX 11
  o IRIX
  o AIX 4.3.3.0/PowerPC
  o BeOS R5
  o Mac OS X 10 - 10.9.3

  NOTE: To build on Win32, use the 1.45 source code.  ngrep 1.46.1 hasn't been
        updated for Win32 yet.

  1.45 works on: Windows 95, 98, NT, 2000, XP, 2003/x86, 7


Support, Feedback, & Patches

  If you need help, have constructive feedback, or would like to submit a patch,
  please visit ngrep's project at SourceForge and use the online tools there.
  It will help the author better manage the various requests and patches so that
  nothing is lost or missed (as has been the case in the past, unfortunately).

  ngrep Project Website:

    http://sourceforge.net/projects/ngrep/
