/*
 * Copyright (c) 2025  Matej Bellus <matej.bellus@gmail.com>
 *
 * Please refer to the LICENSE file for more information.
 *
 * Container name resolution for Docker/Podman containers
 */

#ifndef CONTAINER_RESOLUTION_H
#define CONTAINER_RESOLUTION_H

#include <stdint.h>
#include <stddef.h>

/*
 * Public API for container name resolution
 */

/* Initialize the container cache - call before using resolution */
int container_resolution_init(void);

/* Format an IP address with its container name if available */
void container_format_ip(const char* ip_addr, char* output, size_t output_size);

/* Refresh the container cache manually (optional - automatic refresh happens on TTL expiry) */
int container_refresh_cache(void);

/* Cleanup - call on shutdown (optional) */
void container_cleanup(void);

#endif /* CONTAINER_RESOLUTION_H */
