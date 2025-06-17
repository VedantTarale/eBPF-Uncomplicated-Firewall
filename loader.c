#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if.h>

#define PROGRAM_PATH "tc_firewall.o"
#define DEFAULT_INTERFACE "wlan0"


struct ip_port_key {
    uint32_t ip;    
    uint16_t port; 
};

struct config {
    char interface[IFNAMSIZ];
    char **allowed_ips;
    int num_ips;
    int port;
    int verbose;
};

// Function to print usage
void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS] COMMAND\n", prog_name);
    printf("\nCommands:\n");
    printf("  load     Load the eBPF firewall\n");
    printf("  unload   Unload the eBPF firewall\n");
    printf("  status   Show firewall status\n");
    printf("  add-ip   Add an IP:port combination to allowed list\n");
    printf("  del-ip   Remove an IP:port combination from allowed list\n");
    printf("  disable-port Disable Egress on the port\n");
    printf("  enable-port  Enable Egress on the port\n");
    printf("  list-ips List allowed IP:port combinations\n");
    printf("\nOptions:\n");
    printf("  -i IFACE    Network interface (default: %s)\n", DEFAULT_INTERFACE);
    printf("  -p PORT     Port number (required for add-ip/del-ip commands)\n");
    printf("  -a IP       IP address (required for add-ip/del-ip commands)\n");
    printf("  -v          Verbose output\n");
    printf("  -h          Show this help\n");
    printf("\nExamples:\n");
    printf("  %s -i wlan0 load\n", prog_name);
    printf("  %s -a 192.168.1.10 -p 8080 add-ip\n", prog_name);
    printf("  %s -a 192.168.1.10 -p 8080 del-ip\n", prog_name);
    printf("  %s status\n", prog_name);
}

// Function to convert IP string to network byte order
int ip_to_int(const char *ip_str, uint32_t *ip_int) {
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) {
        return -1;
    }
    *ip_int = addr.s_addr;  // Already in network byte order
    return 0;
}

// Function to convert network byte order to IP string
void int_to_ip(uint32_t ip_int, char *ip_str) {
    struct in_addr addr;
    addr.s_addr = ip_int;
    strcpy(ip_str, inet_ntoa(addr));
}

// Function to find the allowed_ips map
int find_map_fd(const char *map_name) {
    struct bpf_map_info info = {};
    uint32_t info_len = sizeof(info);
    uint32_t id = 0;
    int fd, err;

    while (true) {
        err = bpf_map_get_next_id(id, &id);
        if (err) {
            if (errno == ENOENT) {
                break;
            }
            return -1;
        }

        fd = bpf_map_get_fd_by_id(id);
        if (fd < 0) {
            continue;
        }

        err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
        if (err) {
            close(fd);
            continue;
        }

        if (strcmp(info.name, map_name) == 0) {
            return fd;
        }
        close(fd);
    }
    return -1;
}

// Function to add IP:port combination to allowed list
int add_ip(struct config *cfg, const char *ip_str, int port) {
    int map_fd;
    uint32_t value = 1;  // Changed from uint8_t to uint32_t to match BPF program
    int err;
    struct ip_port_key key = {0};

    if (cfg->verbose) {
        printf("Adding IP:port %s:%d to allowed list\n", ip_str, port);
    }

    // Convert IP string to network byte order
    if (ip_to_int(ip_str, &key.ip) < 0) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return -1;
    }
    
    // Set port in network byte order (matching BPF program expectation)
    key.port = htons(port);
    
    if (cfg->verbose) {
        printf("Key: IP=0x%08x, Port=%d (0x%04x)\n", 
               ntohl(key.ip), ntohs(key.port), key.port);
    }
    
    // Find the map
    map_fd = find_map_fd("allowed_ips");
    if (map_fd < 0) {
        fprintf(stderr, "Could not find allowed_ips map. Is the program loaded and attached?\n");
        fprintf(stderr, "Make sure to run the 'tc' commands to attach the program first.\n");
        return -1;
    }

    // Update the map
    err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (err) {
        fprintf(stderr, "Error updating map: %s\n", strerror(errno));
        close(map_fd);
        return -1;
    }

    printf("Successfully added IP:port %s:%d\n", ip_str, port);
    close(map_fd);
    return 0;
}

int add_port(struct config *cfg, int port){
    int map_fd;
    uint32_t value = 1;
    int err;

    if (cfg->verbose) {
        printf("Adding port %d to allowed egress list\n", port);
    }    
    
    int network_port = htons(port);

    // Find the map
    map_fd = find_map_fd("disabled_egress");
    if (map_fd < 0) {
        fprintf(stderr, "Could not find disabled_egress map. Is the program loaded and attached?\n");
        fprintf(stderr, "Make sure to run the 'tc' commands to attach the program first.\n");
        return -1;
    }

    err = bpf_map_update_elem(map_fd, &network_port, &value, BPF_ANY);
    if (err) {
        fprintf(stderr, "Error updating map: %s\n", strerror(errno));
        close(map_fd);
        return -1;
    }

    printf("Successfully added port %d in disabled egress ports list\n", port);
    close(map_fd);
    return 0;
}

// Function to remove IP:port combination from allowed list
int del_ip(struct config *cfg, const char *ip_str, int port) {
    int map_fd;
    struct ip_port_key key = {0};
    int err;

    if (cfg->verbose) {
        printf("Removing IP:port %s:%d from allowed list\n", ip_str, port);
    }

    // Convert IP string to network byte order
    if (ip_to_int(ip_str, &key.ip) < 0) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return -1;
    }
    
    // Set port in network byte order
    key.port = htons(port);

    // Find the map
    map_fd = find_map_fd("allowed_ips");
    if (map_fd < 0) {
        fprintf(stderr, "Could not find allowed_ips map. Is the program loaded and attached?\n");
        return -1;
    }

    // Delete from the map
    err = bpf_map_delete_elem(map_fd, &key);
    if (err) {
        if (errno == ENOENT) {
            fprintf(stderr, "IP:port %s:%d not found in allowed list\n", ip_str, port);
        } else {
            fprintf(stderr, "Error deleting from map: %s\n", strerror(errno));
        }
        close(map_fd);
        return -1;
    }

    printf("Successfully removed IP:port %s:%d\n", ip_str, port);
    close(map_fd);
    return 0;
}

int del_port(int port) {
    int map_fd;
    int err;

    
    // Set port in network byte order
    int network_port = htons(port);

    // Find the map
    map_fd = find_map_fd("disabled_egress");
    if (map_fd < 0) {
        fprintf(stderr, "Could not find disabled_egress map. Is the program loaded and attached?\n");
        return -1;
    }

    // Delete from the map
    err = bpf_map_delete_elem(map_fd, &network_port);
    if (err) {
        if (errno == ENOENT) {
            fprintf(stderr, "Port %d not found in disaled egress ports list\n", port);
        } else {
            fprintf(stderr, "Error deleting from map: %s\n", strerror(errno));
        }
        close(map_fd);
        return -1;
    }

    printf("Successfully removed port %d from blocked egress list\n", port);
    close(map_fd);
    return 0;
}

// Function to list allowed IP:port combinations
int list_ips() {
    int map_fd;
    struct ip_port_key key, next_key;
    uint32_t value;  // Changed from uint8_t to uint32_t
    char ip_str[INET_ADDRSTRLEN];
    int err;
    int count = 0;

    // Find the map
    map_fd = find_map_fd("allowed_ips");
    if (map_fd < 0) {
        fprintf(stderr, "Could not find allowed_ips map. Is the program loaded and attached?\n");
        return -1;
    }

    printf("Allowed IP:port combinations:\n");
    printf("=============================\n");

    // Initialize key for iteration
    memset(&key, 0, sizeof(key));
    
    // Try to get first key
    err = bpf_map_get_next_key(map_fd, NULL, &key);
    if (err) {
        if (errno == ENOENT) {
            printf("  (none)\n");
            close(map_fd);
            return 0;
        } else {
            fprintf(stderr, "Error iterating map: %s\n", strerror(errno));
            close(map_fd);
            return -1;
        }
    }

    // Process first entry
    err = bpf_map_lookup_elem(map_fd, &key, &value);
    if (err == 0) {
        int_to_ip(key.ip, ip_str);
        printf("  %s:%d\n", ip_str, ntohs(key.port));
        count++;
    }
    
    // Iterate through remaining entries
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        err = bpf_map_lookup_elem(map_fd, &next_key, &value);
        if (err == 0) {
            int_to_ip(next_key.ip, ip_str);
            printf("  %s:%d\n", ip_str, ntohs(next_key.port));
            count++;
        }
        key = next_key;
    }

    if (count == 0) {
        printf("  (none)\n");
    } else {
        printf("\nTotal: %d IP:port combination(s)\n", count);
    }

    close(map_fd);
    return 0;
}

// Function to list allowed egress ports
int list_ports() {
    int map_fd;
    struct ip_port_key key, next_key;
    uint32_t value;  // Changed from uint8_t to uint32_t
    char ip_str[INET_ADDRSTRLEN];
    int err;
    int count = 0;

    // Find the map
    map_fd = find_map_fd("disabled_egress");
    if (map_fd < 0) {
        fprintf(stderr, "Could not find disabled_egress map. Is the program loaded and attached?\n");
        return -1;
    }

    printf("Blocked egress ports:\n");
    printf("=============================\n");

    // Initialize key for iteration
    memset(&key, 0, sizeof(key));
    
    // Try to get first key
    err = bpf_map_get_next_key(map_fd, NULL, &key);
    if (err) {
        if (errno == ENOENT) {
            printf("  (none)\n");
            close(map_fd);
            return 0;
        } else {
            fprintf(stderr, "Error iterating map: %s\n", strerror(errno));
            close(map_fd);
            return -1;
        }
    }

    // Process first entry
    err = bpf_map_lookup_elem(map_fd, &key, &value);
    if (err == 0) {
        int_to_ip(key.ip, ip_str);
        printf("  %s:%d\n", ip_str, ntohs(key.port));
        count++;
    }
    
    // Iterate through remaining entries
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        err = bpf_map_lookup_elem(map_fd, &next_key, &value);
        if (err == 0) {
            int_to_ip(next_key.ip, ip_str);
            printf("  %s:%d\n", ip_str, ntohs(next_key.port));
            count++;
        }
        key = next_key;
    }

    if (count == 0) {
        printf("  (none)\n");
    } else {
        printf("\nTotal: %d ports \n", count);
    }

    close(map_fd);
    return 0;
}

// Function to show status
int show_status(struct config *cfg) {
    printf("TC eBPF Firewall Status\n");
    printf("=======================\n");
    printf("Interface: %s\n", cfg->interface);
    printf("Default Port: %d\n", cfg->port);
    printf("\n");
    
    list_ips();
    list_ports();
    return 0;

}

int main(int argc, char **argv) {
    struct config cfg = {
        .port = 8080,
        .verbose = 0
    };
    
    // Set default interface
    strncpy(cfg.interface, DEFAULT_INTERFACE, IFNAMSIZ - 1);
    cfg.interface[IFNAMSIZ - 1] = '\0';
    
    char *ip_addr = NULL;
    char *command = NULL;
    int port_specified = 0;
    int opt;

    // Parse command line options
    while ((opt = getopt(argc, argv, "i:p:a:vh")) != -1) {
        switch (opt) {
            case 'i':
                strncpy(cfg.interface, optarg, IFNAMSIZ - 1);
                cfg.interface[IFNAMSIZ - 1] = '\0';
                break;
            case 'p':
                cfg.port = atoi(optarg);
                port_specified = 1;
                if (cfg.port <= 0 || cfg.port > 65535) {
                    fprintf(stderr, "Error: Port must be between 1 and 65535\n");
                    return 1;
                }
                break;
            case 'a':
                ip_addr = optarg;
                break;
            case 'v':
                cfg.verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Get command
    if (optind >= argc) {
        fprintf(stderr, "Error: No command specified\n");
        print_usage(argv[0]);
        return 1;
    }
    command = argv[optind];

    // Execute command
    if (strcmp(command, "status") == 0) {
        return show_status(&cfg);
    } else if (strcmp(command, "add-ip") == 0) {
        if (!ip_addr) {
            fprintf(stderr, "Error: IP address required for add-ip command (-a option)\n");
            return 1;
        }
        if (!port_specified) {
            fprintf(stderr, "Error: Port number required for add-ip command (-p option)\n");
            return 1;
        }
        return add_ip(&cfg, ip_addr, cfg.port);
    } else if (strcmp(command, "del-ip") == 0) {
        if (!ip_addr) {
            fprintf(stderr, "Error: IP address required for del-ip command (-a option)\n");
            return 1;
        }
        if (!port_specified) {
            fprintf(stderr, "Error: Port number required for del-ip command (-p option)\n");
            return 1;
        }
        return del_ip(&cfg, ip_addr, cfg.port);
    } else if (strcmp(command, "list-ips") == 0) {
        return list_ips();
    } else if (strcmp(command, "list-ports") == 0)
    {
        return list_ports();
    } else if (strcmp(command,"disable-port") == 0){
        if (!port_specified) {
            fprintf(stderr, "Error: Port number required for add-ip command (-p option)\n");
            return 1;
        }
        return add_port(&cfg, cfg.port);
    } else if (strcmp(command,"enable-port") == 0){
        if (!port_specified) {
            fprintf(stderr, "Error: Port number required for add-ip command (-p option)\n");
            return 1;
        }
        return del_port(cfg.port);
    }
    else {
        fprintf(stderr, "Error: Unknown command '%s'\n", command);
        print_usage(argv[0]);
        return 1;
    }

}