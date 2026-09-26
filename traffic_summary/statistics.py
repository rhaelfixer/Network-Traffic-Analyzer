from collections import defaultdict


# =================================
# Protocol Statistics
# =================================
def calculate_protocol_statistics(packets):
    protocols = {}

    protocol_layers = {
        "IPv4": "IP",
        "IPv6": "IPv6",
        "ARP": "ARP",
        "TCP": "TCP",
        "UDP": "UDP",
        "SCTP": "SCTP",
        "ICMP": "ICMP",
        "ICMPv6": "ICMPv6",
    }

    for protocol_name, layer_name in protocol_layers.items():
        packet_count = 0
        byte_count = 0

        for packet in packets:
            if packet.haslayer(layer_name):
                packet_count += 1
                byte_count += len(packet)

        if packet_count > 0:
            protocols[protocol_name] = {
                "packets": packet_count,
                "bytes": byte_count,
            }

    # =================================
    # Application Protocols
    # =================================
    application_protocols = {
        "DNS": 0,
        "HTTP": 0,
        "HTTPS": 0,
        "DHCP": 0,
        "SSH": 0,
    }

    application_bytes = {
        "DNS": 0,
        "HTTP": 0,
        "HTTPS": 0,
        "DHCP": 0,
        "SSH": 0,
    }

    for packet in packets:
        packet_size = len(packet)

        if packet.haslayer("DNS"):
            application_protocols["DNS"] += 1
            application_bytes["DNS"] += packet_size

        if packet.haslayer("TCP"):
            tcp = packet["TCP"]

            ports = {
                tcp.sport,
                tcp.dport,
            }

            if 80 in ports:
                application_protocols["HTTP"] += 1
                application_bytes["HTTP"] += packet_size

            if 443 in ports:
                application_protocols["HTTPS"] += 1
                application_bytes["HTTPS"] += packet_size

            if 22 in ports:
                application_protocols["SSH"] += 1
                application_bytes["SSH"] += packet_size

        if packet.haslayer("UDP"):
            udp = packet["UDP"]

            ports = {
                udp.sport,
                udp.dport,
            }

            if 67 in ports or 68 in ports:
                application_protocols["DHCP"] += 1
                application_bytes["DHCP"] += packet_size

    for protocol, packet_count in application_protocols.items():
        if packet_count > 0:
            protocols[protocol] = {
                "packets": packet_count,
                "bytes": application_bytes[protocol],
            }

    return protocols


# =================================
# IP Statistics
# =================================
def calculate_ip_statistics(packets):
    source_data = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
        }
    )

    destination_data = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
        }
    )

    source_ips = set()
    destination_ips = set()

    # =================================
    # Process IP Packets
    # =================================
    for packet in packets:
        source = None
        destination = None

        if packet.haslayer("IP"):
            source = packet["IP"].src
            destination = packet["IP"].dst

        elif packet.haslayer("IPv6"):
            source = packet["IPv6"].src
            destination = packet["IPv6"].dst

        if source is None or destination is None:
            continue

        packet_size = len(packet)

        source_ips.add(source)
        destination_ips.add(destination)

        source_data[source]["packets"] += 1
        source_data[source]["bytes"] += packet_size

        destination_data[destination]["packets"] += 1
        destination_data[destination]["bytes"] += packet_size

    # =================================
    # Sort IPs
    # =================================
    source_ips_sorted = sorted(
        source_data.items(),
        key=lambda item: item[1]["bytes"],
        reverse=True,
    )

    destination_ips_sorted = sorted(
        destination_data.items(),
        key=lambda item: item[1]["bytes"],
        reverse=True,
    )

    # =================================
    # IP Versions
    # =================================
    ipv4_packets = 0
    ipv4_bytes = 0

    ipv6_packets = 0
    ipv6_bytes = 0

    for packet in packets:
        if packet.haslayer("IP"):
            ipv4_packets += 1
            ipv4_bytes += len(packet)

        elif packet.haslayer("IPv6"):
            ipv6_packets += 1
            ipv6_bytes += len(packet)

    return {
        "unique_source_ips": len(source_ips),
        "unique_destination_ips": len(destination_ips),
        "source_ips": source_ips_sorted,
        "destination_ips": destination_ips_sorted,
        "ipv4_packets": ipv4_packets,
        "ipv4_bytes": ipv4_bytes,
        "ipv6_packets": ipv6_packets,
        "ipv6_bytes": ipv6_bytes,
    }


# =================================
# TCP Statistics
# =================================
def calculate_tcp_statistics(packets):
    tcp_packets = 0

    syn = 0
    syn_ack = 0
    ack = 0
    fin = 0
    rst = 0
    psh = 0
    urg = 0

    source_ports = defaultdict(int)
    destination_ports = defaultdict(int)

    tcp_flows = set()

    total_tcp_bytes = 0

    for packet in packets:
        if not packet.haslayer("TCP"):
            continue

        tcp_packets += 1

        tcp = packet["TCP"]
        flags = int(tcp.flags)

        total_tcp_bytes += len(packet)

        # =================================
        # TCP Flags
        # =================================
        if flags & 0x02:
            syn += 1

        if flags & 0x12 == 0x12:
            syn_ack += 1

        if flags & 0x10:
            ack += 1

        if flags & 0x01:
            fin += 1

        if flags & 0x04:
            rst += 1

        if flags & 0x08:
            psh += 1

        if flags & 0x20:
            urg += 1

        # =================================
        # TCP Ports
        # =================================
        source_ports[tcp.sport] += 1
        destination_ports[tcp.dport] += 1

        # =================================
        # TCP Flow
        # =================================
        source = None
        destination = None

        if packet.haslayer("IP"):
            source = packet["IP"].src
            destination = packet["IP"].dst

        elif packet.haslayer("IPv6"):
            source = packet["IPv6"].src
            destination = packet["IPv6"].dst

        if source is not None:
            endpoints = tuple(
                sorted(
                    [
                        (source, tcp.sport),
                        (destination, tcp.dport),
                    ]
                )
            )

            tcp_flows.add(endpoints)

    top_source_ports = sorted(
        source_ports.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    top_destination_ports = sorted(
        destination_ports.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    return {
        "packets": tcp_packets,
        "bytes": total_tcp_bytes,
        "syn": syn,
        "syn_ack": syn_ack,
        "ack": ack,
        "fin": fin,
        "rst": rst,
        "psh": psh,
        "urg": urg,
        "unique_flows": len(tcp_flows),
        "source_ports": top_source_ports,
        "destination_ports": top_destination_ports,
    }


# =================================
# Conversation Statistics
# =================================
def calculate_conversation_statistics(packets):
    conversations = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
            "first_timestamp": None,
            "last_timestamp": None,
        }
    )

    for packet in packets:
        source = None
        destination = None

        protocol = None

        source_port = None
        destination_port = None

        # =================================
        # IP Information
        # =================================
        if packet.haslayer("IP"):
            source = packet["IP"].src
            destination = packet["IP"].dst

        elif packet.haslayer("IPv6"):
            source = packet["IPv6"].src
            destination = packet["IPv6"].dst

        if source is None or destination is None:
            continue

        # =================================
        # Transport Information
        # =================================
        if packet.haslayer("TCP"):
            protocol = "TCP"
            source_port = packet["TCP"].sport
            destination_port = packet["TCP"].dport

        elif packet.haslayer("UDP"):
            protocol = "UDP"
            source_port = packet["UDP"].sport
            destination_port = packet["UDP"].dport

        else:
            protocol = "IP"

        # =================================
        # Normalize Conversation
        # =================================
        endpoint_a = (
            source,
            source_port,
        )

        endpoint_b = (
            destination,
            destination_port,
        )

        endpoints = tuple(
            sorted(
                [
                    endpoint_a,
                    endpoint_b,
                ]
            )
        )

        key = (
            protocol,
            endpoints,
        )

        timestamp = float(packet.time)

        conversations[key]["packets"] += 1
        conversations[key]["bytes"] += len(packet)

        if conversations[key]["first_timestamp"] is None:
            conversations[key]["first_timestamp"] = timestamp

        conversations[key]["last_timestamp"] = timestamp

    # =================================
    # Convert to List
    # =================================
    results = []

    for (
        (protocol, endpoints),
        data,
    ) in conversations.items():
        first_timestamp = data["first_timestamp"]
        last_timestamp = data["last_timestamp"]

        duration = (
            last_timestamp - first_timestamp if first_timestamp is not None else 0
        )

        source, source_port = endpoints[0]
        destination, destination_port = endpoints[1]

        results.append(
            {
                "protocol": protocol,
                "source": source,
                "source_port": source_port,
                "destination": destination,
                "destination_port": destination_port,
                "packets": data["packets"],
                "bytes": data["bytes"],
                "duration": duration,
            }
        )

    results.sort(
        key=lambda item: item["bytes"],
        reverse=True,
    )

    return results


# =================================
# Complete Traffic Analysis
# =================================
def analyze_packets(packets):
    total_packets = len(packets)

    if total_packets == 0:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "duration": 0,
            "average_packet_size": 0,
            "minimum_packet_size": 0,
            "maximum_packet_size": 0,
            "packets_per_second": 0,
            "bytes_per_second": 0,
            "peak_packets_per_second": 0,
            "peak_bytes_per_second": 0,
            "protocols": {},
            "ip": calculate_ip_statistics([]),
            "tcp": calculate_tcp_statistics([]),
            "conversations": [],
        }

    # =================================
    # Packet Size Statistics
    # =================================
    packet_sizes = [len(packet) for packet in packets]

    total_bytes = sum(packet_sizes)

    average_packet_size = total_bytes / total_packets

    minimum_packet_size = min(packet_sizes)
    maximum_packet_size = max(packet_sizes)

    # =================================
    # Capture Duration
    # =================================
    first_timestamp = float(packets[0].time)
    last_timestamp = float(packets[-1].time)

    duration = last_timestamp - first_timestamp

    if duration > 0:
        packets_per_second = total_packets / duration

        bytes_per_second = total_bytes / duration

    else:
        packets_per_second = 0
        bytes_per_second = 0

    # =================================
    # Peak Traffic Rate
    # =================================
    packet_counts = defaultdict(int)
    byte_counts = defaultdict(int)

    for packet in packets:
        second = int(float(packet.time))

        packet_counts[second] += 1
        byte_counts[second] += len(packet)

    peak_packets_per_second = max(
        packet_counts.values(),
        default=0,
    )

    peak_bytes_per_second = max(
        byte_counts.values(),
        default=0,
    )

    # =================================
    # Detailed Statistics
    # =================================
    protocols = calculate_protocol_statistics(packets)

    ip_statistics = calculate_ip_statistics(packets)

    tcp_statistics = calculate_tcp_statistics(packets)

    conversations = calculate_conversation_statistics(packets)

    return {
        # Capture overview
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "duration": duration,
        "average_packet_size": average_packet_size,
        "minimum_packet_size": minimum_packet_size,
        "maximum_packet_size": maximum_packet_size,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "peak_packets_per_second": peak_packets_per_second,
        "peak_bytes_per_second": peak_bytes_per_second,
        # Detailed statistics
        "protocols": protocols,
        "ip": ip_statistics,
        "tcp": tcp_statistics,
        "conversations": conversations,
    }
