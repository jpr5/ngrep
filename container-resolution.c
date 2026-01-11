/*
 * Copyright (c) 2025  Matej Bellus <matej.bellus@gmail.com>
 *
 * Please refer to the LICENSE file for more information.
 *
 * Container name resolution for Docker/Podman containers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#define HAVE_UNIX_SOCKETS 1
#else
#define HAVE_UNIX_SOCKETS 0
#endif

#include "container-resolution.h"

/* Reference to ngrep's quiet flag */
extern uint8_t quiet;

/*
 * Container Resolution Data Structures
 */

#define MAX_CONTAINERS 1024
#define MAX_CONTAINER_NAME 64
#define MAX_IP_ADDR_LEN 64
#define MAX_CONTAINER_ID 65
#define DEFAULT_CACHE_TTL 30

#define DOCKER_SOCKET_PATH "/var/run/docker.sock"
#define PODMAN_SOCKET_PATH "/run/podman/podman.sock"

struct container_entry {
    char ip_addr[MAX_IP_ADDR_LEN];
    char container_name[MAX_CONTAINER_NAME];
    char container_id[MAX_CONTAINER_ID];
    time_t last_seen;
};

struct container_cache {
    struct container_entry entries[MAX_CONTAINERS];
    uint32_t count;
    time_t last_refresh;
};

/* Global container cache */
static struct container_cache g_container_cache = {0};
static const uint32_t cache_ttl = DEFAULT_CACHE_TTL;

/* Docker socket for real-time events */
static int docker_events_fd = -1;
static int using_realtime_events = 0;
static char event_buffer[4096];
static size_t event_buffer_len = 0;
/* Runtime used for socket/events + inspect commands ("docker" or "podman") */
static const char *event_runtime = "docker";

/* Forward declarations for internal functions */
static const char* lookup_container_name(const char* ip_addr);
static void cleanup_expired_cache_entries(void);
static int discover_containers_via_cli(void);
static int discover_containers_for_runtime(const char *runtime, uint32_t *cache_idx);

/* Docker socket event functions */
static int connect_to_docker_socket(void);
static int setup_docker_events_stream(void);
static void process_docker_events(void);
static void handle_container_event(const char *event_json);
static int add_container_by_id(const char *container_id);
static void remove_container_by_id(const char *container_id);
static char* extract_json_string(const char *json, const char *key);
static int is_valid_container_id(const char *id);

/*
 * Public API Implementation
 */

int container_resolution_init(void) {
    /* Ensure we don't leak any previous socket/event state */
    container_cleanup();

    /* Clear current cache */
    memset(&g_container_cache, 0, sizeof(g_container_cache));
    g_container_cache.last_refresh = time(NULL);

    /* Try to set up real-time events via Docker socket first */
    if (setup_docker_events_stream() == 0) {
        using_realtime_events = 1;
        if (!quiet)
            fprintf(stderr, "container: using docker socket for real-time events\n");
    } else {
        using_realtime_events = 0;
        if (!quiet)
            fprintf(stderr, "container: using CLI polling (TTL=%ds)\n", cache_ttl);
    }

    /* Discover existing containers via Docker/Podman CLI commands */
    return discover_containers_via_cli();
}

int container_refresh_cache(void) {
    return container_resolution_init();
}

void container_cleanup(void) {
#if HAVE_UNIX_SOCKETS
    if (docker_events_fd >= 0) {
        close(docker_events_fd);
        docker_events_fd = -1;
    }
#endif
    using_realtime_events = 0;
    event_buffer_len = 0;
    memset(&g_container_cache, 0, sizeof(g_container_cache));
}

void container_format_ip(const char* ip_addr, char* output, size_t output_size) {
    const char* container_name;

    if (!ip_addr || !output || output_size == 0) {
        if (output && output_size > 0) {
            output[0] = '\0';
        }
        return;
    }

    /* Try to resolve container name */
    container_name = lookup_container_name(ip_addr);

    if (container_name && strlen(container_name) > 0) {
        /* Format as: container_name(ip_addr) */
        snprintf(output, output_size, "%s(%s)", container_name, ip_addr);
    } else {
        /* Just use the IP address */
        strncpy(output, ip_addr, output_size - 1);
        output[output_size - 1] = '\0';
    }
}

/*
 * Internal Implementation
 */

static const char* lookup_container_name(const char* ip_addr) {
    if (!ip_addr) {
        return NULL;
    }

    time_t now = time(NULL);

    /* Process any pending docker events (non-blocking) */
    if (using_realtime_events && docker_events_fd >= 0) {
        process_docker_events();
    }

    /* Check if cache needs refresh (only if not using real-time events) */
    if (!using_realtime_events && (now - g_container_cache.last_refresh > cache_ttl)) {
        container_refresh_cache();
    }

    /* Cleanup expired entries (only if not using real-time events) */
    if (!using_realtime_events) {
        cleanup_expired_cache_entries();
    }

    /* Search cache for IP address */
    for (uint32_t i = 0; i < g_container_cache.count; i++) {
        if (strcmp(g_container_cache.entries[i].ip_addr, ip_addr) == 0) {
            /* Update last seen timestamp */
            g_container_cache.entries[i].last_seen = now;
            return g_container_cache.entries[i].container_name;
        }
    }

    return NULL;
}

static void cleanup_expired_cache_entries(void) {
    time_t now = time(NULL);
    uint32_t write_idx = 0;

    for (uint32_t read_idx = 0; read_idx < g_container_cache.count; read_idx++) {
        if (now - g_container_cache.entries[read_idx].last_seen <= cache_ttl) {
            if (write_idx != read_idx) {
                g_container_cache.entries[write_idx] = g_container_cache.entries[read_idx];
            }
            write_idx++;
        }
    }

    g_container_cache.count = write_idx;
}

/*
 * Discover containers for a specific runtime (docker or podman).
 * Returns 0 on success, -1 on failure. Updates cache_idx with new count.
 */
static int discover_containers_for_runtime(const char *runtime, uint32_t *cache_idx) {
    FILE *fp;
    char line[512];
    char cmd[512];

    snprintf(cmd, sizeof(cmd), "%s ps --format '{{.ID}}:{{.Names}}' --no-trunc 2>/dev/null", runtime);
    fp = popen(cmd, "r");
    if (!fp) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) && *cache_idx < MAX_CONTAINERS) {
        /* Remove newline */
        line[strcspn(line, "\n")] = '\0';

        /* Parse ID:Name format */
        char *colon = strchr(line, ':');
        if (!colon || strlen(line) == 0) continue;

        *colon = '\0';
        char *container_id = line;
        char *container_name = colon + 1;

        if (strlen(container_name) > 0) {
            /* For each container, get IP addresses */
            snprintf(cmd, sizeof(cmd),
                    "%s inspect %s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null",
                    runtime, container_id);

            FILE *inspect_fp = popen(cmd, "r");
            if (inspect_fp) {
                char ips[256];
                if (fgets(ips, sizeof(ips), inspect_fp)) {
                    char *ip = strtok(ips, " \n");
                    while (ip && *cache_idx < MAX_CONTAINERS) {
                        if (strlen(ip) > 0) {
                            strncpy(g_container_cache.entries[*cache_idx].container_name,
                                   container_name, MAX_CONTAINER_NAME - 1);
                            g_container_cache.entries[*cache_idx].container_name[MAX_CONTAINER_NAME - 1] = '\0';

                            strncpy(g_container_cache.entries[*cache_idx].ip_addr,
                                   ip, MAX_IP_ADDR_LEN - 1);
                            g_container_cache.entries[*cache_idx].ip_addr[MAX_IP_ADDR_LEN - 1] = '\0';

                            strncpy(g_container_cache.entries[*cache_idx].container_id,
                                   container_id, MAX_CONTAINER_ID - 1);
                            g_container_cache.entries[*cache_idx].container_id[MAX_CONTAINER_ID - 1] = '\0';

                            g_container_cache.entries[*cache_idx].last_seen = time(NULL);
                            (*cache_idx)++;
                        }
                        ip = strtok(NULL, " \n");
                    }
                }
                pclose(inspect_fp);
            }
        }
    }
    pclose(fp);

    return 0;
}

static int discover_containers_via_cli(void) {
    uint32_t cache_idx = 0;

    /* Try Docker first */
    discover_containers_for_runtime("docker", &cache_idx);

    /* Try Podman if Docker didn't find containers */
    if (cache_idx == 0) {
        discover_containers_for_runtime("podman", &cache_idx);
    }

    g_container_cache.count = cache_idx;
    /* "No containers found" is not an error; leave cache empty. */
    return 0;
}

/*
 * Docker Socket Event Handling
 */

#if HAVE_UNIX_SOCKETS

static int connect_to_docker_socket(void) {
    int fd;
    struct sockaddr_un addr;
    const char *socket_path = DOCKER_SOCKET_PATH;

    /* Try Docker socket first */
    event_runtime = "docker";
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);

        /* Try Podman socket as fallback */
        socket_path = PODMAN_SOCKET_PATH;
        event_runtime = "podman";
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            return -1;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(fd);
            return -1;
        }
    }

    return fd;
}

static int setup_docker_events_stream(void) {
    const char *request =
        "GET /events?filters=%7B%22type%22%3A%5B%22container%22%5D%2C%22event%22%3A%5B%22start%22%2C%22die%22%5D%7D HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    char response[1024];
    ssize_t n;

    docker_events_fd = connect_to_docker_socket();
    if (docker_events_fd < 0) {
        return -1;
    }

    /* Send the events request */
    if (write(docker_events_fd, request, strlen(request)) < 0) {
        close(docker_events_fd);
        docker_events_fd = -1;
        return -1;
    }

    /* Read the HTTP response header */
    n = read(docker_events_fd, response, sizeof(response) - 1);
    if (n <= 0) {
        close(docker_events_fd);
        docker_events_fd = -1;
        return -1;
    }
    response[n] = '\0';

    /* Check for successful response */
    if (strstr(response, "200 OK") == NULL) {
        close(docker_events_fd);
        docker_events_fd = -1;
        return -1;
    }

    /* Set socket to non-blocking mode */
    int flags = fcntl(docker_events_fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(docker_events_fd, F_SETFL, flags | O_NONBLOCK);
    }

    event_buffer_len = 0;
    return 0;
}

static void process_docker_events(void) {
    char buf[1024];
    ssize_t n;

    if (docker_events_fd < 0) {
        return;
    }

    /* Read available data (non-blocking) */
    while ((n = read(docker_events_fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';

        /* Append to event buffer */
        size_t space = sizeof(event_buffer) - event_buffer_len - 1;
        if ((size_t)n > space) {
            n = space;
        }
        if (n > 0) {
            memcpy(event_buffer + event_buffer_len, buf, n);
            event_buffer_len += n;
            event_buffer[event_buffer_len] = '\0';
        }
    }

    /* Check for connection error (not EAGAIN/EWOULDBLOCK) */
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        close(docker_events_fd);
        docker_events_fd = -1;
        using_realtime_events = 0;
        return;
    }

    /* Process complete JSON objects in the buffer */
    char *start = event_buffer;
    char *newline;

    while ((newline = strchr(start, '\n')) != NULL) {
        *newline = '\0';

        /* Skip chunked encoding size lines (hex numbers) */
        if (start[0] != '{') {
            start = newline + 1;
            continue;
        }

        handle_container_event(start);
        start = newline + 1;
    }

    /* Move remaining data to the beginning of the buffer */
    if (start != event_buffer && start < event_buffer + event_buffer_len) {
        size_t remaining = event_buffer_len - (start - event_buffer);
        memmove(event_buffer, start, remaining);
        event_buffer_len = remaining;
        event_buffer[event_buffer_len] = '\0';
    } else if (start == event_buffer + event_buffer_len) {
        event_buffer_len = 0;
        event_buffer[0] = '\0';
    }
}

/*
 * Extract a string value from JSON by key.
 * WARNING: Returns pointer to static buffer - copy result before calling again!
 */
static char* extract_json_string(const char *json, const char *key) {
    static char value[256];
    char search_key[128];
    const char *start, *end;

    snprintf(search_key, sizeof(search_key), "\"%s\":\"", key);
    start = strstr(json, search_key);
    if (!start) {
        /* Try without quotes for nested objects */
        snprintf(search_key, sizeof(search_key), "\"%s\":", key);
        start = strstr(json, search_key);
        if (!start) {
            return NULL;
        }
        start += strlen(search_key);
        /* Skip whitespace */
        while (*start == ' ' || *start == '\t') start++;
        if (*start != '"') {
            return NULL;
        }
        start++;
    } else {
        start += strlen(search_key);
    }

    end = strchr(start, '"');
    if (!end || (size_t)(end - start) >= sizeof(value)) {
        return NULL;
    }

    size_t len = end - start;
    memcpy(value, start, len);
    value[len] = '\0';
    return value;
}

static void handle_container_event(const char *event_json) {
    /* NOTE: extract_json_string() uses a static buffer; copy immediately. */
    char *status = extract_json_string(event_json, "status");
    char status_copy[32];

    if (!status) {
        return;
    }

    strncpy(status_copy, status, sizeof(status_copy) - 1);
    status_copy[sizeof(status_copy) - 1] = '\0';

    char *container_id = extract_json_string(event_json, "id");

    if (!container_id) {
        return;
    }

    /* Make a copy of container_id since extract_json_string uses static buffer */
    char id_copy[MAX_CONTAINER_ID];
    strncpy(id_copy, container_id, sizeof(id_copy) - 1);
    id_copy[sizeof(id_copy) - 1] = '\0';

    if (strcmp(status_copy, "start") == 0) {
        add_container_by_id(id_copy);
    } else if (strcmp(status_copy, "die") == 0) {
        remove_container_by_id(id_copy);
    }
}

#else /* !HAVE_UNIX_SOCKETS */

/* Stub implementations for Windows */
static int setup_docker_events_stream(void) { return -1; }
static void process_docker_events(void) { }

#endif /* HAVE_UNIX_SOCKETS */

/* Validate container ID to prevent command injection.
 * Docker container IDs are 64 hex characters (or 12 char short form).
 * Container names can contain [a-zA-Z0-9][a-zA-Z0-9_.-]* */
static int is_valid_container_id(const char *id) {
    size_t len;
    size_t i;

    if (!id) return 0;

    len = strlen(id);
    if (len == 0 || len > 64) return 0;

    for (i = 0; i < len; i++) {
        char c = id[i];
        /* Allow alphanumeric, underscore, dash, dot for container IDs and names */
        if (!((c >= '0' && c <= '9') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') ||
              c == '_' || c == '-' || c == '.')) {
            return 0;
        }
    }
    return 1;
}

static int add_container_by_id(const char *container_id) {
    char cmd[512];
    FILE *fp;
    char name[MAX_CONTAINER_NAME];
    char ips[256];

    if (g_container_cache.count >= MAX_CONTAINERS) {
        return -1;
    }

    /* Validate container ID to prevent command injection */
    if (!is_valid_container_id(container_id)) {
        return -1;
    }

    /* Get container name */
    snprintf(cmd, sizeof(cmd),
        "%s inspect %s --format '{{.Name}}' 2>/dev/null",
        event_runtime, container_id);

    fp = popen(cmd, "r");
    if (!fp) {
        return -1;
    }

    if (!fgets(name, sizeof(name), fp)) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    name[strcspn(name, "\n")] = '\0';
    /* Docker/Podman prefix names with '/', strip it to match CLI `.Names` */
    if (name[0] == '/') {
        memmove(name, name + 1, strlen(name));
    }

    if (strlen(name) == 0) {
        return -1;
    }

    /* Get container IP addresses */
    snprintf(cmd, sizeof(cmd),
        "%s inspect %s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null",
        event_runtime, container_id);

    fp = popen(cmd, "r");
    if (!fp) {
        return -1;
    }

    if (!fgets(ips, sizeof(ips), fp)) {
        pclose(fp);
        return -1;
    }
    pclose(fp);

    /* Add each IP to the cache */
    char *ip = strtok(ips, " \n");
    while (ip && g_container_cache.count < MAX_CONTAINERS) {
        if (strlen(ip) > 0) {
            uint32_t idx = g_container_cache.count;
            strncpy(g_container_cache.entries[idx].container_name, name, MAX_CONTAINER_NAME - 1);
            g_container_cache.entries[idx].container_name[MAX_CONTAINER_NAME - 1] = '\0';
            strncpy(g_container_cache.entries[idx].ip_addr, ip, MAX_IP_ADDR_LEN - 1);
            g_container_cache.entries[idx].ip_addr[MAX_IP_ADDR_LEN - 1] = '\0';
            strncpy(g_container_cache.entries[idx].container_id, container_id, MAX_CONTAINER_ID - 1);
            g_container_cache.entries[idx].container_id[MAX_CONTAINER_ID - 1] = '\0';
            g_container_cache.entries[idx].last_seen = time(NULL);
            g_container_cache.count++;
        }
        ip = strtok(NULL, " \n");
    }

    return 0;
}

static void remove_container_by_id(const char *container_id) {
    uint32_t write_idx = 0;

    for (uint32_t read_idx = 0; read_idx < g_container_cache.count; read_idx++) {
        if (strcmp(g_container_cache.entries[read_idx].container_id, container_id) != 0) {
            if (write_idx != read_idx) {
                g_container_cache.entries[write_idx] = g_container_cache.entries[read_idx];
            }
            write_idx++;
        }
    }

    g_container_cache.count = write_idx;
}
