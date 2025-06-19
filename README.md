# eBPF-Uncomplicated-Firewall
This project is an eBPF-based Traffic Control (TC) firewall, inspired by the Linux Uncomplicated Firewall(UFW), using the `classifier/ingress` and `classifier/egress` hooks. It filters packets based on allowed IP-port pairs and ports, and logs per-packet latency using a ring buffer.

## Table of Contents
- [Overview](#overview)
- [Data Structures](#data-structures)
- [Maps](#maps)
- [Ingress Logic](#ingress-logic)
- [Egress Logic](#egress-logic)
- [Ring Buffer Logging](#ring-buffer-logging)
- [Usage Notes](#usage-notes)
- [Makefile Guide](#makefile-guide)
- [Firewall Loader](#tc-firewall-loader--ebpf-firewall-control-cli)

---

## Overview

This firewall program:
- Blocks unauthorized TCP/UDP traffic on both ingress and egress.
- Maintains two BPF maps:
  - `allowed_ips` for IP+port whitelisting.
  - `allowed_ports` for global port whitelisting.
- Automatically updates port permissions if egress is successful.
- Emits per-packet latency metrics through a `BPF_MAP_TYPE_RINGBUF`.

---

## Data Structures

### `struct ip_port_key`
```c
struct ip_port_key {
    __u32 ip;     // IPv4 address
    __u16 port;   // TCP/UDP port
};
```

### `struct event`
```c
struct event {
    __u64 latency_ns;  // Latency in nanoseconds
    __u8 direction;    // 0 for ingress, 1 for egress
};
```

---

## Maps
> Maps listed below are all `Pinned By Name`
### `allowed_ips`
Hash map of allowed `(IP, Port)` combinations.
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOWED_IP_PORT_PAIRS);
    __type(key, struct ip_port_key);
    __type(value, __u32); //Non-zero value => allow
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} allowed_ips SEC(".maps");
```

### `allowed_ports`
LRU hash map of allowed ports and their direction.
```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_EGRESS_PORTS);
    __type(key, __u16);
    __type(value, __u32); // Egress(1), Ingress(2), Igress and Egress(3)
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} allowed_ports SEC(".maps");
```

### `events`
Ring buffer used for exporting latency events.
```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");
```

---

## Ring Buffer Logging

Both ingress and egress paths write an `event` structure to a shared ring buffer to track processing time per packet.

### Sample Entry
```json
{
  "latency_ns": 2350,
  "direction": 0
}
```

Direction:  
- `0`: Ingress  
- `1`: Egress

---

## Usage Notes

- **Port whitelisting**:
  - You can allow all ingress traffic to a port by inserting the port with value `INGRESS`.
  - Similarly for `EGRESS` or `INGRESS_AND_EGRESS`.

- **IP-Port whitelisting**:
  - Used as a fallback when port-only rule is not present.

- **Performance**:
  - Uses LRU maps for egress ports to minimize memory usage.
  - Ring buffer avoids perf event overhead.

---

## Makefile Guide
### Build Targets

| Target | Description |
|--------|-------------|
| `all` | Build both kernel and userspace programs |
| `clean` | Remove build artifacts |

---

### Installation Targets (Require Root)

| Target | Description |
|--------|-------------|
| `install` | Load firewall and setup default IPs |
| `load` | Load firewall only |
| `unload` | Unload firewall |
| `remove_maps` | Remove pinned BPF maps |

---

### Management Targets

| Target | Description |
|--------|-------------|
| `status` | Show firewall status |
| `show-filters` | Show current TC filters |

---

### Variables

| Variable | Description |
|----------|-------------|
| `INTERFACE` | Network interface to apply firewall (default: `wlan0`) |

Override example:
```bash
make load INTERFACE=eth0
```
---

## `tc-firewall-loader` — eBPF Firewall Control CLI

A utility to manage an eBPF-based firewall with IP and port control features.

### Commands

| Command    | Description                                      |
|------------|--------------------------------------------------|
| `load`     | Load the eBPF firewall onto the interface.       |
| `unload`   | Unload the eBPF firewall from the interface.     |
| `status`   | Show current firewall status.                    |
| `add-ip`   | Add an IP:port combination to the allowlist.     |
| `del-ip`   | Remove an IP:port combination from the allowlist.|
| `add-port` | Disable **egress** traffic on a port.            |
| `del-port` | Enable **egress** traffic on a port.             |
| `list-ips` | List all allowed IP:port combinations.           |

### Options

| Option        | Description                                                                 |
|---------------|-----------------------------------------------------------------------------|
| `-i IFACE`    | Network interface to operate on (default: `enp2s0`)                         |
| `-p PORT`     | Port number (required for `add-ip` / `del-ip` commands)                    |
| `-a IP`       | IP address (required for `add-ip` / `del-ip` commands)                     |
| `-v`          | Enable verbose output                                                       |
| `-d DIRECTION`| Direction for port blocking (only for `add-port`):                         |
|               | &nbsp;&nbsp;&nbsp;&nbsp;`1` → Egress                                       |
|               | &nbsp;&nbsp;&nbsp;&nbsp;`2` → Ingress                                      |
|               | &nbsp;&nbsp;&nbsp;&nbsp;`3` → Both directions                              |
| `-h`          | Show help message                                                           |

### Examples

```bash
# Load the firewall on interface enp2s0
./tc-firewall-loader -i enp2s0 load

# Add an IP:port pair to allowlist
./tc-firewall-loader -a 192.168.1.10 -p 8080 add-ip

# Remove an IP:port pair from allowlist
./tc-firewall-loader -a 192.168.1.10 -p 8080 del-ip

# List all allowlisted IP:port pairs
./tc-firewall-loader list-ips

# Disable egress traffic on port 443
./tc-firewall-loader -p 443 -d 1 add-port

# Enable egress traffic on port 443
./tc-firewall-loader -p 443 del-port

# Show firewall status
./tc-firewall-loader status
```