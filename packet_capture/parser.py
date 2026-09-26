from scapy.all import (
    ARP,
    ICMP,
    IP,
    SCTP,
    TCP,
    UDP,
    IPv6,
)

# =================================
# Protocol Definitions
# =================================
NETWORK_PROTOCOLS = [
    (IP, "IPv4"),
    (IPv6, "IPv6"),
    (ARP, "ARP"),
    (ICMP, "ICMP"),
]

TRANSPORT_PROTOCOLS = [
    (TCP, "TCP"),
    (UDP, "UDP"),
    (SCTP, "SCTP"),
]

ADDRESS_FIELDS = [
    (IP, "src", "dst"),
    (IPv6, "src", "dst"),
    (ARP, "psrc", "pdst"),
]


# =================================
# Protocol Identification
# =================================
def get_protocol(packet, protocols):
    for protocol, name in protocols:
        if protocol in packet:
            return name

    return "-"


# =================================
# Address Parsing
# =================================
def get_packet_addresses(packet):
    for protocol, source_field, destination_field in ADDRESS_FIELDS:
        if protocol in packet:
            layer = packet[protocol]

            source = getattr(layer, source_field)
            destination = getattr(layer, destination_field)

            return source, destination

    return "-", "-"


# =================================
# IPv4 Parsing
# =================================
def parse_ipv4(packet):
    if IP not in packet:
        return {}

    ip = packet[IP]

    return {
        "version": ip.version,
        "ihl": ip.ihl,
        "tos": ip.tos,
        "length": ip.len,
        "id": ip.id,
        "flags": str(ip.flags),
        "fragment_offset": ip.frag,
        "ttl": ip.ttl,
        "protocol": ip.proto,
        "checksum": ip.chksum,
    }


# =================================
# IPv6 Parsing
# =================================
def parse_ipv6(packet):
    if IPv6 not in packet:
        return {}

    ipv6 = packet[IPv6]

    return {
        "version": ipv6.version,
        "traffic_class": ipv6.tc,
        "flow_label": ipv6.fl,
        "payload_length": ipv6.plen,
        "next_header": ipv6.nh,
        "hop_limit": ipv6.hlim,
    }


# =================================
# TCP Parsing
# =================================
def parse_tcp(packet):
    if TCP not in packet:
        return {}

    tcp = packet[TCP]

    return {
        "source_port": tcp.sport,
        "destination_port": tcp.dport,
        "sequence": tcp.seq,
        "acknowledgment": tcp.ack,
        "data_offset": tcp.dataofs,
        "reserved": tcp.reserved,
        "flags": str(tcp.flags),
        "window": tcp.window,
        "checksum": tcp.chksum,
        "urgent_pointer": tcp.urgptr,
    }


# =================================
# UDP Parsing
# =================================
def parse_udp(packet):
    if UDP not in packet:
        return {}

    udp = packet[UDP]

    return {
        "source_port": udp.sport,
        "destination_port": udp.dport,
        "length": udp.len,
        "checksum": udp.chksum,
    }


# =================================
# SCTP Parsing
# =================================
def parse_sctp(packet):
    if SCTP not in packet:
        return {}

    sctp = packet[SCTP]

    return {
        "source_port": sctp.sport,
        "destination_port": sctp.dport,
        "verification_tag": sctp.tag,
        "checksum": sctp.chksum,
    }


# =================================
# ICMP Parsing
# =================================
def parse_icmp(packet):
    if ICMP not in packet:
        return {}

    icmp = packet[ICMP]

    return {
        "type": icmp.type,
        "code": icmp.code,
        "checksum": icmp.chksum,
        "identifier": icmp.id,
        "sequence": icmp.seq,
    }


# =================================
# ARP Parsing
# =================================
def parse_arp(packet):
    if ARP not in packet:
        return {}

    arp = packet[ARP]

    return {
        "operation": arp.op,
        "source_mac": arp.hwsrc,
        "source_ip": arp.psrc,
        "destination_mac": arp.hwdst,
        "destination_ip": arp.pdst,
    }


# =================================
# Packet Parser
# =================================
PACKET_PARSERS = [
    (IP, "ipv4", parse_ipv4),
    (IPv6, "ipv6", parse_ipv6),
    (TCP, "tcp", parse_tcp),
    (UDP, "udp", parse_udp),
    (SCTP, "sctp", parse_sctp),
    (ICMP, "icmp", parse_icmp),
    (ARP, "arp", parse_arp),
]


# =================================
# Packet Parsing
# =================================
def parse_packet(packet):
    source, destination = get_packet_addresses(packet)

    parsed_packet = {
        "size": len(packet),
        "source": source,
        "destination": destination,
        "network": get_protocol(packet, NETWORK_PROTOCOLS),
        "transport": get_protocol(packet, TRANSPORT_PROTOCOLS),
        "source_port": "-",
        "destination_port": "-",
    }

    # Parse protocol-specific information
    for protocol, name, parser in PACKET_PARSERS:
        if protocol in packet:
            parsed_packet[name] = parser(packet)

    # Extract generic transport ports
    for protocol, name in TRANSPORT_PROTOCOLS:
        if protocol in packet:
            layer = packet[protocol]

            parsed_packet["source_port"] = layer.sport
            parsed_packet["destination_port"] = layer.dport

            break

    return parsed_packet
