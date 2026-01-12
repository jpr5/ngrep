/*
 * $Id: inet_ntop.h,v 1.1 2005/04/27 22:29:58 jpr5 Exp $
 *
 * Compatibility header, supporting WinXX-specific inet_ntop() implementation.
 */

int inet_ntop(int af, const void *src, char *dst, size_t size);
