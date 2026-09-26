import os
from datetime import datetime

from scapy.all import AsyncSniffer, wrpcap

from packet_capture.packet_display import (
    display_packet,
    print_table_header,
)
from packet_capture.parser import parse_packet

# =================================
# Capture Configuration
# =================================
BPF_FILTERS = {
    "all": None,
    # Network
    "ipv4": "ip",
    "ipv6": "ip6",
    "icmp": "icmp",
    "icmp6": "icmp6",
    "arp": "arp",
    # Transport
    "tcp": "tcp",
    "udp": "udp",
    "sctp": "sctp",
    # Application
    "dns": "port 53",
    "http": "tcp port 80",
    "https": "tcp port 443",
    "dhcp": "udp port 67 or udp port 68",
    "ssh": "tcp port 22",
}


CAPTURE_NAMES = {
    "all": "All Traffic",
    # Network
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "icmp": "ICMP",
    "icmp6": "ICMPv6",
    "arp": "ARP",
    # Transport
    "tcp": "TCP",
    "udp": "UDP",
    "sctp": "SCTP",
    # Application
    "dns": "DNS",
    "http": "HTTP",
    "https": "HTTPS",
    "dhcp": "DHCP",
    "ssh": "SSH",
}


# =================================
# Capture Utility
# =================================
def get_bpf_filter(capture_type):
    return BPF_FILTERS[capture_type]


def get_capture_name(capture_type):
    return CAPTURE_NAMES[capture_type]


# =================================
# Capture Saving
# =================================
def save_capture(packets):
    if not packets:
        return None

    if not os.path.exists("./captures"):
        os.makedirs("./captures")
        print()
        print("[*] Created captures folder.")

    else:
        print()
        print("[*] Captures folder already exists.")

    timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")

    filename = f"{timestamp}.pcap"

    filepath = f"./captures/{filename}"

    wrpcap(filepath, packets)

    print(f"[*] Capture saved to {filepath}")

    return filepath


# =================================
# Packet Processing
# =================================
def packet_callback(packet, capture_type, packets):
    packets.append(packet)

    parsed_packet = parse_packet(packet)

    display_packet(
        parsed_packet,
        capture_type,
    )


# =================================
# Packet Capture
# =================================
def capture_packets(
    capture_type,
    duration=None,
    wait_for_input=True,
):
    bpf_filter = get_bpf_filter(capture_type)
    display_name = get_capture_name(capture_type)

    print(f"[*] Starting {display_name} packet capture...")

    if duration is None:
        print("[*] Duration: Unlimited")

    else:
        print(f"[*] Duration: {duration} seconds")

    print("[*] Press CTRL+C to stop.")
    print()

    print_table_header(capture_type)

    # Store captured packets ourselves.
    packets = []

    sniffer = AsyncSniffer(
        filter=bpf_filter,
        prn=lambda packet: packet_callback(
            packet,
            capture_type,
            packets,
        ),
    )

    try:
        sniffer.start()

        if duration is None:
            sniffer.join()

        else:
            sniffer.join(timeout=duration)

            if sniffer.running:
                sniffer.stop()

        filepath = save_capture(packets)

        print("[*] Packet capture completed.")
        print()

    except KeyboardInterrupt:
        if sniffer.running:
            sniffer.stop()

        filepath = save_capture(packets)

        print("[*] Packet capture stopped.")
        print()

    if wait_for_input:
        input("Press ENTER to return to the Packet Capture Menu...")

    return packets, filepath


# =================================
# Custom Packet Capture
# =================================
def capture_custom_packets(
    bpf_filter,
    duration=None,
    wait_for_input=True,
):
    print("[*] Starting custom BPF packet capture...")
    print(f"[*] BPF Filter: {bpf_filter}")

    if duration is None:
        print("[*] Duration: Unlimited")

    else:
        print(f"[*] Duration: {duration} seconds")

    print("[*] Press CTRL+C to stop.")
    print()

    # Custom filters don't correspond to one fixed capture type, so use the generic table.
    table_type = "all"

    print_table_header(table_type)

    # Store captured packets ourselves.
    packets = []

    sniffer = AsyncSniffer(
        filter=bpf_filter,
        prn=lambda packet: packet_callback(
            packet,
            table_type,
            packets,
        ),
    )

    try:
        sniffer.start()

        if duration is None:
            sniffer.join()

        else:
            sniffer.join(timeout=duration)

            if sniffer.running:
                sniffer.stop()

        filepath = save_capture(packets)

        print("[*] Packet capture completed.")
        print()

    except KeyboardInterrupt:
        if sniffer.running:
            sniffer.stop()

        filepath = save_capture(packets)

        print("[*] Packet capture stopped.")
        print()

    if wait_for_input:
        input("Press ENTER to return to the Packet Capture Menu...")

    return packets, filepath
