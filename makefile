CC = gcc
CLANG = clang
CFLAGS = -Wall -Wextra -O2 -g
BPF_CFLAGS = -O2 -target bpf -g
LDFLAGS = -lbpf -lelf

KERNEL_SRC = tc_firewall.c
USER_SRC = loader.c
KERNEL_OBJ = tc_firewall.o
USER_BIN = tc-firewall-loader

ifndef INTERFACE
	INTERFACE = wlan0
endif

.PHONY: all load unload remove_maps show-filters install status clean help

all: $(KERNEL_OBJ) $(USER_BIN)
$(KERNEL_OBJ): $(KERNEL_SRC)
	@echo "Compiling eBPF kernel program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "eBPF program compiled: $@"

$(USER_BIN): $(USER_SRC)
	@echo "Compiling userspace loader..."
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	@echo "Userspace loader compiled: $@"

load: $(KERNEL_OBJ) $(USER_BIN)
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: This must be run as root"; \
		exit 1; \
	fi
	@echo "Loading TC eBPF firewall on interface $(INTERFACE)..."
	
	# Reset qdisc
	-tc qdisc del dev $(INTERFACE) clsact 2>/dev/null	
	tc qdisc add dev $(INTERFACE) clsact

	# Add ingress and egress classifiers
	tc filter add dev $(INTERFACE) ingress bpf da obj $(KERNEL_OBJ) sec classifier/ingress
	tc filter add dev $(INTERFACE) egress bpf da obj $(KERNEL_OBJ) sec classifier/egress

	@echo "Firewall loaded successfully on $(INTERFACE)"

	@echo "Adding default allowed IPs and egress ports..."
	sudo ./$(USER_BIN) -a 192.168.2.217 -p 80 add-ip
	sudo ./$(USER_BIN) -p 80 -d 3 add-port
	sudo ./$(USER_BIN) -p 443 -d 3 add-port
	@echo "Default IPs and Egress Ports added"

unload:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: This target must be run as root"; \
		exit 1; \
	fi
	@echo "Unloading TC eBPF firewall from interface $(INTERFACE)..."
	-tc qdisc del dev $(INTERFACE) clsact 2>/dev/null
	@echo "Firewall unloaded from $(INTERFACE)"

remove_maps:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: This target must be run as root"; \
		exit 1; \
	fi
	@echo "Removing Pinned Maps"
	-rm -f /sys/fs/bpf/tc/globals/allowed_ips
	-rm -f /sys/fs/bpf/tc/globals/allowed_ports
	@echo "Maps removed successfully"

show-filters:
	@echo "TC filters on $(INTERFACE):"
	@tc filter show dev $(INTERFACE) ingress 2>/dev/null || echo "No filters found"


install: all load
	@echo "Firewall installation complete!"
	@echo "Use './$(USER_BIN) status' to check firewall status"

status: $(USER_BIN)
	@./$(USER_BIN) -i $(INTERFACE) status

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(KERNEL_OBJ) $(USER_BIN)
	@echo "Clean complete"

help:
	@echo "TC eBPF Firewall Makefile"
	@echo "========================="
	@echo ""
	@echo "Build targets:"
	@echo "  all          - Build both kernel and userspace programs"
	@echo "  clean        - Remove build artifacts"
	@echo ""
	@echo "Installation targets:"
	@echo "  install      - Load firewall and setup default IPs (requires root)"
	@echo "  load         - Load firewall only (requires root)"
	@echo "  unload       - Unload firewall (requires root)"
	@echo "  remove_maps  - Remove pinned maps (requires root)"
	@echo "  setup-ips    - Add default allowed IPs (requires root)"
	@echo ""
	@echo "Management targets:"
	@echo "  status       - Show firewall status"
	@echo "  show-filters - Show current TC filters"
	@echo ""
	@echo "Variables:"
	@echo "  INTERFACE    - Network interface (default: wlan0)"
	@echo ""

.PRECIOUS: $(KERNEL_OBJ)