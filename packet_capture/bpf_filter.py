from scapy.arch.common import compile_filter
from scapy.error import Scapy_Exception

from utils.menu_display import MENU_WIDTH


# =================================
# BPF Filter Input
# =================================
def get_custom_bpf_filter():
    print("=" * MENU_WIDTH)
    print("Custom BPF Filter".center(MENU_WIDTH))
    print("=" * MENU_WIDTH)
    print()

    print("Enter a BPF filter.".center(MENU_WIDTH))
    print("Examples:".center(MENU_WIDTH))

    examples = [
        # Protocol
        "tcp",
        "udp",
        "icmp",
        "arp",
        # Port
        "tcp port 443",
        "udp port 53",
        "src port 443",
        "dst port 443",
        # Host
        "host 10.0.0.5",
        "src host 10.0.0.5",
        "dst host 10.0.0.5",
        # Network
        "net 10.0.0.0/24",
        # Combinations
        "tcp and port 443",
        "tcp and host 10.0.0.5",
        "udp and port 53",
        "tcp or udp",
        "not port 22",
    ]

    example_width = max(map(len, examples))
    padding = (MENU_WIDTH - example_width) // 2

    for example in examples:
        print(" " * padding + example)

    print()

    while True:
        bpf_filter = input("BPF Filter: ").strip()

        if not bpf_filter:
            print()
            print("BPF filter cannot be empty.")
            print()
            continue

        try:
            compile_filter(bpf_filter)

        except (Scapy_Exception, ValueError):
            print()
            print("Invalid BPF filter.")
            print("Please enter a valid BPF expression.")
            print()
            continue

        return bpf_filter
