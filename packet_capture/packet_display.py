from datetime import datetime

# =================================
# Table Configuration
# =================================
COLUMN_GAP = 3

TABLES = {
    # =================================
    # All Traffic
    # =================================
    "all": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("NETWORK", 10),
        ("TRANSPORT", 10),
        ("SRC PORT", 10),
        ("DST PORT", 10),
        ("SIZE", 8),
    ],
    # =================================
    # Network
    # =================================
    "ipv4": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("IHL", 6),
        ("TOS", 6),
        ("LENGTH", 8),
        ("ID", 10),
        ("FLAGS", 8),
        ("FRAG", 8),
        ("TTL", 6),
        ("PROTO", 8),
        ("SIZE", 8),
    ],
    "ipv6": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("TC", 6),
        ("FLOW LABEL", 12),
        ("PAYLOAD", 10),
        ("NEXT HEADER", 12),
        ("HOP LIMIT", 10),
        ("SIZE", 8),
    ],
    "icmp": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("TYPE", 8),
        ("CODE", 8),
        ("ID", 10),
        ("SEQ", 10),
        ("SIZE", 8),
    ],
    "icmp6": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("SIZE", 8),
    ],
    "arp": [
        ("TIME", 10),
        ("SOURCE IP", 18),
        ("DESTINATION IP", 18),
        ("OPERATION", 12),
        ("SOURCE MAC", 20),
        ("DESTINATION MAC", 20),
        ("SIZE", 8),
    ],
    # =================================
    # Transport
    # =================================
    "tcp": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("SRC PORT", 10),
        ("DST PORT", 10),
        ("FLAGS", 8),
        ("SEQ", 12),
        ("ACK", 12),
        ("WINDOW", 10),
        ("SIZE", 8),
    ],
    "udp": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("SRC PORT", 10),
        ("DST PORT", 10),
        ("LENGTH", 8),
        ("CHECKSUM", 12),
        ("SIZE", 8),
    ],
    "sctp": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("SRC PORT", 10),
        ("DST PORT", 10),
        ("VERIFICATION TAG", 18),
        ("CHECKSUM", 12),
        ("SIZE", 8),
    ],
    # =================================
    # Application
    # =================================
    "dns": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("SRC PORT", 10),
        ("DST PORT", 10),
        ("LENGTH", 8),
        ("SIZE", 8),
    ],
    "http": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("SRC PORT", 10),
        ("DST PORT", 10),
        ("FLAGS", 8),
        ("SEQ", 12),
        ("ACK", 12),
        ("SIZE", 8),
    ],
    "https": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("SRC PORT", 10),
        ("DST PORT", 10),
        ("FLAGS", 8),
        ("SEQ", 12),
        ("ACK", 12),
        ("SIZE", 8),
    ],
    "dhcp": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("SRC PORT", 10),
        ("DST PORT", 10),
        ("LENGTH", 8),
        ("SIZE", 8),
    ],
    "ssh": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("SRC PORT", 10),
        ("DST PORT", 10),
        ("FLAGS", 8),
        ("SEQ", 12),
        ("ACK", 12),
        ("SIZE", 8),
    ],
    # =================================
    # Generic
    # =================================
    "generic": [
        ("TIME", 10),
        ("SOURCE", 24),
        ("DESTINATION", 24),
        ("NETWORK", 10),
        ("TRANSPORT", 10),
        ("SIZE", 8),
    ],
}


# =================================
# Table Field Configuration
# =================================
TABLE_FIELDS = {
    "all": [
        "timestamp",
        "source",
        "destination",
        "network",
        "transport",
        "source_port",
        "destination_port",
        "size",
    ],
    "ipv4": [
        "timestamp",
        "source",
        "destination",
        ("ipv4", "ihl"),
        ("ipv4", "tos"),
        ("ipv4", "length"),
        ("ipv4", "id"),
        ("ipv4", "flags"),
        ("ipv4", "fragment_offset"),
        ("ipv4", "ttl"),
        ("ipv4", "protocol"),
        "size",
    ],
    "ipv6": [
        "timestamp",
        "source",
        "destination",
        ("ipv6", "traffic_class"),
        ("ipv6", "flow_label"),
        ("ipv6", "payload_length"),
        ("ipv6", "next_header"),
        ("ipv6", "hop_limit"),
        "size",
    ],
    "icmp": [
        "timestamp",
        "source",
        "destination",
        ("icmp", "type"),
        ("icmp", "code"),
        ("icmp", "identifier"),
        ("icmp", "sequence"),
        "size",
    ],
    "icmp6": [
        "timestamp",
        "source",
        "destination",
        "size",
    ],
    "arp": [
        "timestamp",
        ("arp", "source_ip"),
        ("arp", "destination_ip"),
        ("arp", "operation"),
        ("arp", "source_mac"),
        ("arp", "destination_mac"),
        "size",
    ],
    "tcp": [
        "timestamp",
        "source",
        "destination",
        ("tcp", "source_port"),
        ("tcp", "destination_port"),
        ("tcp", "flags"),
        ("tcp", "sequence"),
        ("tcp", "acknowledgment"),
        ("tcp", "window"),
        "size",
    ],
    "udp": [
        "timestamp",
        "source",
        "destination",
        ("udp", "source_port"),
        ("udp", "destination_port"),
        ("udp", "length"),
        ("udp", "checksum"),
        "size",
    ],
    "sctp": [
        "timestamp",
        "source",
        "destination",
        ("sctp", "source_port"),
        ("sctp", "destination_port"),
        ("sctp", "verification_tag"),
        ("sctp", "checksum"),
        "size",
    ],
    "dns": [
        "timestamp",
        "source",
        "destination",
        ("udp", "source_port"),
        ("udp", "destination_port"),
        ("udp", "length"),
        "size",
    ],
    "http": [
        "timestamp",
        "source",
        "destination",
        ("tcp", "source_port"),
        ("tcp", "destination_port"),
        ("tcp", "flags"),
        ("tcp", "sequence"),
        ("tcp", "acknowledgment"),
        "size",
    ],
    "https": [
        "timestamp",
        "source",
        "destination",
        ("tcp", "source_port"),
        ("tcp", "destination_port"),
        ("tcp", "flags"),
        ("tcp", "sequence"),
        ("tcp", "acknowledgment"),
        "size",
    ],
    "dhcp": [
        "timestamp",
        "source",
        "destination",
        ("udp", "source_port"),
        ("udp", "destination_port"),
        ("udp", "length"),
        "size",
    ],
    "ssh": [
        "timestamp",
        "source",
        "destination",
        ("tcp", "source_port"),
        ("tcp", "destination_port"),
        ("tcp", "flags"),
        ("tcp", "sequence"),
        ("tcp", "acknowledgment"),
        "size",
    ],
    "generic": [
        "timestamp",
        "source",
        "destination",
        "network",
        "transport",
        "size",
    ],
}


# =================================
# Field Value
# =================================
def get_field_value(parsed_packet, field, timestamp):

    # Generic timestamp
    if field == "timestamp":
        return timestamp

    # Generic source port
    if field == "source_port":
        return parsed_packet.get("source_port", "-")

    # Generic destination port
    if field == "destination_port":
        return parsed_packet.get("destination_port", "-")

    # Protocol-specific field
    if isinstance(field, tuple):
        protocol, name = field

        protocol_data = parsed_packet.get(protocol, {})

        return protocol_data.get(name, "-")

    # Generic field
    return parsed_packet.get(field, "-")


# =================================
# Table Display
# =================================
def print_table_header(table_type):
    columns = TABLES[table_type]

    header = ""

    for name, width in columns:
        header += f"{name:<{width}}{' ' * COLUMN_GAP}"

    print(header)
    print("-" * len(header))


def print_table_row(values, table_type):
    columns = TABLES[table_type]

    row = ""

    for value, (_, width) in zip(values, columns):
        row += f"{value!s:<{width}}{' ' * COLUMN_GAP}"

    print(row)


# =================================
# Packet Display
# =================================
def display_packet(parsed_packet, table_type):
    timestamp = datetime.now().astimezone().strftime("%H:%M:%S")

    fields = TABLE_FIELDS[table_type]

    values = [
        get_field_value(
            parsed_packet,
            field,
            timestamp,
        )
        for field in fields
    ]

    print_table_row(values, table_type)
