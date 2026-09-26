import os

from traffic_summary.statistics import (
    calculate_conversation_statistics,
    calculate_ip_statistics,
    calculate_protocol_statistics,
    calculate_tcp_statistics,
)
from utils.menu_display import EXTENDED_WIDTH, MENU_WIDTH
from utils.pcap_loader import (
    load_capture,
    select_capture_file,
)


# =================================
# Traffic Summary
# =================================
def traffic_summary():
    filepath = select_capture_file()

    if filepath is None:
        return

    packets = load_capture(filepath)

    if packets is None:
        return

    print()
    print("[*] Analyzing traffic summary...")

    statistics = {
        "protocols": calculate_protocol_statistics(packets),
        "ip": calculate_ip_statistics(packets),
        "tcp": calculate_tcp_statistics(packets),
        "conversations": calculate_conversation_statistics(packets),
    }

    print("[*] Analysis completed.")

    display_summary(
        filepath,
        packets,
        statistics,
    )

    print()
    input("Press ENTER to return to the Traffic Summary Menu...")
    print()


# =================================
# Display Traffic Summary
# =================================
def display_summary(filepath, packets, statistics):
    filename = os.path.basename(filepath)

    total_packets = len(packets)

    if total_packets > 0:
        packet_sizes = [len(packet) for packet in packets]

        total_bytes = sum(packet_sizes)

        average_packet_size = total_bytes / total_packets

        minimum_packet_size = min(packet_sizes)
        maximum_packet_size = max(packet_sizes)

        first_timestamp = float(packets[0].time)
        last_timestamp = float(packets[-1].time)

        duration = last_timestamp - first_timestamp

        if duration > 0:
            packets_per_second = total_packets / duration
            bytes_per_second = total_bytes / duration

        else:
            packets_per_second = 0
            bytes_per_second = 0

    else:
        total_bytes = 0
        average_packet_size = 0
        minimum_packet_size = 0
        maximum_packet_size = 0
        duration = 0
        packets_per_second = 0
        bytes_per_second = 0

    print()
    print("=" * MENU_WIDTH)
    print("TRAFFIC SUMMARY".center(MENU_WIDTH))
    print("=" * MENU_WIDTH)
    print()

    print(f"{'Capture File:':<22}{filename}")
    print()


    # =================================
    # Capture Overview
    # =================================
    print("-" * MENU_WIDTH)
    print("CAPTURE OVERVIEW")
    print("-" * MENU_WIDTH)

    print(f"{'Packets:':<25}{total_packets:>10}")
    print(f"{'Total Bytes:':<25}{total_bytes:>10}")
    print(f"{'Duration:':<25}{duration:>10.2f} seconds")
    print(f"{'Average Packet Size:':<25}{average_packet_size:>10.2f} bytes")
    print(f"{'Minimum Packet Size:':<25}{minimum_packet_size:>10} bytes")
    print(f"{'Maximum Packet Size:':<25}{maximum_packet_size:>10} bytes")

    print()

    print(f"{'Packets / Second:':<25}{packets_per_second:>10.2f}")
    print(f"{'Bytes / Second:':<25}{bytes_per_second:>10.2f}")

    print()


    # =================================
    # Protocol Overview
    # =================================
    print("-" * MENU_WIDTH)
    print("PROTOCOL OVERVIEW")
    print("-" * MENU_WIDTH)

    for protocol, data in statistics["protocols"].items():
        print(
            f"{protocol + ':':<15}"
            f"{data['packets']:>10} packets"
            f"{data['bytes']:>12} bytes"
        )

    print()


    # =================================
    # IP Activity
    # =================================
    print("-" * MENU_WIDTH)
    print("IP ACTIVITY")
    print("-" * MENU_WIDTH)

    ip_stats = statistics["ip"]

    print(f"{'Unique Source IPs:':<35}{ip_stats['unique_source_ips']}")
    print(
        f"{'Unique Destination IPs:':<35}"
        f"{ip_stats['unique_destination_ips']}"
    )

    print()


    # =================================
    # TCP Statistics
    # =================================
    print("-" * MENU_WIDTH)
    print("TCP STATISTICS")
    print("-" * MENU_WIDTH)

    tcp = statistics["tcp"]

    print(f"{'TCP Packets:':<20}{tcp['packets']}")
    print(f"{'SYN:':<20}{tcp['syn']}")
    print(f"{'SYN-ACK:':<20}{tcp['syn_ack']}")
    print(f"{'ACK:':<20}{tcp['ack']}")
    print(f"{'FIN:':<20}{tcp['fin']}")
    print(f"{'RST:':<20}{tcp['rst']}")

    print()


    # =================================
    # Conversations
    # =================================
    print("-" * MENU_WIDTH)
    print("TOP CONVERSATIONS")
    print("-" * MENU_WIDTH)

    for conversation in statistics["conversations"][:10]:
        source = conversation["source"]
        destination = conversation["destination"]
        packet_count = conversation["packets"]
        byte_count = conversation["bytes"]

        print(
            f"{source:>15}"
            f"{'->':^6}"
            f"{destination:<15}"
            f"{packet_count:>6} packets"
            f"{byte_count:>10} bytes"
        )

    print()
    print("=" * MENU_WIDTH)


# =================================
# Protocol Statistics
# =================================
def protocol_statistics():
    filepath = select_capture_file()

    if filepath is None:
        return

    packets = load_capture(filepath)

    if packets is None:
        return

    print()
    print("[*] Analyzing protocol statistics...")

    statistics = calculate_protocol_statistics(packets)

    print("[*] Analysis completed.")

    display_protocol_statistics(
        filepath,
        statistics,
        len(packets),
    )

    print()
    input("Press ENTER to return to the Traffic Summary Menu...")
    print()


# =================================
# Display Protocol Statistics
# =================================
def display_protocol_statistics(
    filepath,
    statistics,
    total_packets,
):
    filename = os.path.basename(filepath)

    print()
    print("=" * MENU_WIDTH)
    print("PROTOCOL STATISTICS".center(MENU_WIDTH))
    print("=" * MENU_WIDTH)
    print()

    print(f"{'Capture File:':<22}{filename}")
    print()

    print("-" * MENU_WIDTH)
    print("PROTOCOL BREAKDOWN")
    print("-" * MENU_WIDTH)

    for protocol, data in statistics.items():
        percentage = (
            data["packets"] / total_packets * 100
            if total_packets > 0
            else 0
        )

        print(
            f"{protocol + ':':<12}"
            f"{data['packets']:>8} packets"
            f"{data['bytes']:>12} bytes"
            f"{percentage:>8.2f}%"
        )

    print()
    print("=" * MENU_WIDTH)


# =================================
# IP Statistics
# =================================
def ip_statistics():
    filepath = select_capture_file()

    if filepath is None:
        return

    packets = load_capture(filepath)

    if packets is None:
        return

    print()
    print("[*] Analyzing IP statistics...")

    statistics = calculate_ip_statistics(packets)

    print("[*] Analysis completed.")

    display_ip_statistics(
        filepath,
        statistics,
    )

    print()
    input("Press ENTER to return to the Traffic Summary Menu...")
    print()


# =================================
# Display IP Statistics
# =================================
def display_ip_statistics(filepath, statistics):
    filename = os.path.basename(filepath)

    print()
    print("=" * MENU_WIDTH)
    print("IP STATISTICS".center(MENU_WIDTH))
    print("=" * MENU_WIDTH)
    print()

    print(f"{'Capture File:':<22}{filename}")
    print()

    # =================================
    # IP Overview
    # =================================
    print("-" * MENU_WIDTH)
    print("IP OVERVIEW")
    print("-" * MENU_WIDTH)

    print(f"{'Unique Source IPs:':<27}{statistics['unique_source_ips']}")
    print(f"{'Unique Destination IPs:':<27}{statistics['unique_destination_ips']}")
    print(f"{'IPv4 Packets:':<27}{statistics['ipv4_packets']}")
    print(f"{'IPv4 Bytes:':<27}{statistics['ipv4_bytes']}")
    print(f"{'IPv6 Packets:':<27}{statistics['ipv6_packets']}")
    print(f"{'IPv6 Bytes:':<27}{statistics['ipv6_bytes']}")

    print()


    # =================================
    # Source IPs
    # =================================
    print("-" * MENU_WIDTH)
    print("TOP SOURCE IPs")
    print("-" * MENU_WIDTH)

    for ip, data in statistics["source_ips"][:10]:
        print(
            f"{ip:<20}"
            f"{data['packets']:>8} packets"
            f"{data['bytes']:>10} bytes"
        )

    print()


    # =================================
    # Destination IPs
    # =================================
    print("-" * MENU_WIDTH)
    print("TOP DESTINATION IPs")
    print("-" * MENU_WIDTH)

    for ip, data in statistics["destination_ips"][:10]:
        print(
            f"{ip:<20}"
            f"{data['packets']:>8} packets"
            f"{data['bytes']:>10} bytes"
        )

    print()
    print("=" * MENU_WIDTH)


# =================================
# TCP Statistics
# =================================
def tcp_statistics():
    filepath = select_capture_file()

    if filepath is None:
        return

    packets = load_capture(filepath)

    if packets is None:
        return

    print()
    print("[*] Analyzing TCP statistics...")

    statistics = calculate_tcp_statistics(packets)

    print("[*] Analysis completed.")

    display_tcp_statistics(
        filepath,
        statistics,
    )

    print()
    input("Press ENTER to return to the Traffic Summary Menu...")
    print()


# =================================
# Display TCP Statistics
# =================================
def display_tcp_statistics(filepath, statistics):
    filename = os.path.basename(filepath)

    print()
    print("=" * MENU_WIDTH)
    print("TCP STATISTICS".center(MENU_WIDTH))
    print("=" * MENU_WIDTH)
    print()

    print(f"{'Capture File:':<22}{filename}")
    print()

    # =================================
    # TCP Overview
    # =================================
    print("-" * MENU_WIDTH)
    print("TCP OVERVIEW")
    print("-" * MENU_WIDTH)

    print(f"{'TCP Packets:':<22}{statistics['packets']:>10}")
    print(f"{'TCP Bytes:':<22}{statistics['bytes']:>10}")
    print(f"{'Unique TCP Flows:':<22}{statistics['unique_flows']:>10}")

    print()

    # =================================
    # TCP Flags
    # =================================
    print("-" * MENU_WIDTH)
    print("TCP FLAGS")
    print("-" * MENU_WIDTH)

    print(f"{'SYN:':<22}{statistics['syn']:>10}")
    print(f"{'SYN-ACK:':<22}{statistics['syn_ack']:>10}")
    print(f"{'ACK:':<22}{statistics['ack']:>10}")
    print(f"{'FIN:':<22}{statistics['fin']:>10}")
    print(f"{'RST:':<22}{statistics['rst']:>10}")
    print(f"{'PSH:':<22}{statistics['psh']:>10}")
    print(f"{'URG:':<22}{statistics['urg']:>10}")

    print()

    # =================================
    # Source Ports
    # =================================
    print("-" * MENU_WIDTH)
    print("TOP SOURCE PORTS")
    print("-" * MENU_WIDTH)

    for port, count in statistics["source_ports"][:10]:
        print(
            f"{f'Port {port}:':<22}"
            f"{count:>10} packets"
        )

    print()

    # =================================
    # Destination Ports
    # =================================
    print("-" * MENU_WIDTH)
    print("TOP DESTINATION PORTS")
    print("-" * MENU_WIDTH)

    for port, count in statistics["destination_ports"][:10]:
        print(
            f"{f'Port {port}:':<22}"
            f"{count:>10} packets"
        )

    print()
    print("=" * MENU_WIDTH)


# =================================
# Conversation Statistics
# =================================
def conversation_statistics():
    filepath = select_capture_file()

    if filepath is None:
        return

    packets = load_capture(filepath)

    if packets is None:
        return

    print()
    print("[*] Analyzing conversation statistics...")

    statistics = calculate_conversation_statistics(packets)

    print("[*] Analysis completed.")

    display_conversation_statistics(
        filepath,
        statistics,
    )

    print()
    input("Press ENTER to return to the Traffic Summary Menu...")
    print()


# =================================
# Display Conversation Statistics
# =================================
def display_conversation_statistics(
    filepath,
    statistics,
):
    filename = os.path.basename(filepath)

    print()
    print("=" * EXTENDED_WIDTH)
    print("CONVERSATION STATISTICS".center(EXTENDED_WIDTH))
    print("=" * EXTENDED_WIDTH)
    print()

    print(f"{'Capture File:':<22}{filename}")
    print()

    print("-" * EXTENDED_WIDTH)
    print("TOP CONVERSATIONS")
    print("-" * EXTENDED_WIDTH)

    for conversation in statistics[:10]:
        source = conversation["source"]
        destination = conversation["destination"]

        protocol = conversation["protocol"]

        source_port = conversation["source_port"]
        destination_port = conversation["destination_port"]

        packet_count = conversation["packets"]
        byte_count = conversation["bytes"]

        print(
            f"{source:>15}"
            f"{'->':^6}"
            f"{destination:<15}"
            f"{protocol:^9}"
            f"{source_port:>6}"
            f"{'->':^6}"
            f"{destination_port:<6}"
            f"{packet_count:>6} packets"
            f"{byte_count:>10} bytes"
        )

    print()
    print("=" * EXTENDED_WIDTH)
