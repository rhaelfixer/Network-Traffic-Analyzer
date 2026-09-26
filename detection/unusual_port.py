from collections import Counter, defaultdict

from config.config import CONFIG


# =================================
# Unusual Port Detection
# =================================
def detect_unusual_ports(packets):
    config = CONFIG.unusual_port

    known_service_ports = CONFIG.known_service_ports
    expected_protocols = CONFIG.expected_protocols
    high_risk_ports = CONFIG.high_risk_ports

    # =================================
    # Port Frequency Tracking
    # =================================
    port_frequency = Counter()
    total_transport_packets = 0

    # =================================
    # Traffic Tracking
    #
    # Aggregate traffic by:
    # source
    # destination
    # protocol
    # destination port
    #
    # Source port is NOT part of the key
    # because client source ports are commonly
    # ephemeral and would fragment traffic
    # into many separate flows.
    # =================================
    flows = defaultdict(
        lambda: {
            "source": None,
            "destination": None,
            "protocol": None,
            "source_port": None,
            "source_ports": set(),
            "destination_port": None,
            "packets": 0,
        }
    )

    # =================================
    # First Pass - Collect Traffic
    # =================================
    for packet in packets:
        source = None
        destination = None

        # =================================
        # IPv4
        # =================================
        if packet.haslayer("IP"):
            source = packet["IP"].src
            destination = packet["IP"].dst

        # =================================
        # IPv6
        # =================================
        elif packet.haslayer("IPv6"):
            source = packet["IPv6"].src
            destination = packet["IPv6"].dst

        else:
            continue

        # =================================
        # Transport Protocol
        # =================================
        if packet.haslayer("TCP"):
            protocol = "TCP"
            source_port = int(packet["TCP"].sport)
            destination_port = int(packet["TCP"].dport)

        elif packet.haslayer("UDP"):
            protocol = "UDP"
            source_port = int(packet["UDP"].sport)
            destination_port = int(packet["UDP"].dport)

        else:
            continue

        total_transport_packets += 1

        # =================================
        # Destination Port Frequency
        # =================================
        port_frequency[destination_port] += 1

        # =================================
        # Flow Key
        # =================================
        key = (
            source,
            destination,
            protocol,
            destination_port,
        )

        flows[key]["source"] = source
        flows[key]["destination"] = destination
        flows[key]["protocol"] = protocol

        # Keep the first source port for compatibility with existing output.
        if flows[key]["source_port"] is None:
            flows[key]["source_port"] = source_port

        # Track all source ports.
        flows[key]["source_ports"].add(source_port)

        flows[key]["destination_port"] = destination_port
        flows[key]["packets"] += 1

    results = []

    # =================================
    # Analyze Flows
    # =================================
    for flow in flows.values():
        destination_port = flow["destination_port"]
        protocol = flow["protocol"]
        packet_count = flow["packets"]

        # =================================
        # Expected Protocol Profile
        # =================================
        port_protocols = expected_protocols.get(
            destination_port
        )

        # =================================
        # Ignore Low-Volume Normal Traffic
        #
        # Low-volume traffic is ignored unless
        # the destination port has an established
        # protocol profile and the observed
        # protocol does not match.
        #
        # Example:
        # UDP -> 993
        # Expected: TCP
        #
        # Protocol mismatches remain relevant even
        # when only a few packets are observed.
        # =================================
        if (
            packet_count < config.min_packets
            and (
                port_protocols is None
                or protocol in port_protocols
            )
        ):
            continue

        # =================================
        # Normal Response Traffic
        #
        # Example:
        #
        # DNS server:
        #     192.168.50.1:53
        #
        # Client:
        #     172.16.0.5:49152
        #
        # Server -> dynamic client port is
        # normal response traffic.
        # =================================
        source_ports = flow["source_ports"]

        if (
            any(
                port in known_service_ports
                for port in source_ports
            )
            and config.dynamic_port_min
            <= destination_port
            <= config.dynamic_port_max
        ):
            continue

        # =================================
        # Known Service
        # =================================
        known_service = known_service_ports.get(
            destination_port
        )

        if known_service is not None:
            service_status = (
                f"Known service: {known_service}"
            )

        else:
            service_status = "Unknown service"

        # =================================
        # Port Frequency
        # =================================
        if total_transport_packets > 0:
            frequency = (
                port_frequency[destination_port]
                / total_transport_packets
            )

        else:
            frequency = 0.0

        # =================================
        # Initialize Score
        # =================================
        score = 0
        reasons = []

        # =================================
        # Port Rarity
        #
        # Rarity is supporting evidence only.
        # =================================
        rarity = "COMMON"

        if (
            frequency
            <= config.very_rare_port_max_frequency
        ):
            rarity = "VERY RARE"

            score += 20

            reasons.append(
                "Destination port is very rare"
            )

        elif (
            frequency
            <= config.rare_port_max_frequency
        ):
            rarity = "RARE"

            score += 10

            reasons.append(
                "Destination port is rare"
            )

        # =================================
        # Unknown Service
        # This means the port is not present
        # in the configured service list.
        # =================================
        if known_service is None:
            reasons.append(
                "Destination port is not in the configured service list"
            )

        # =================================
        # Privileged Port
        # Being in the privileged range does
        # not automatically make a port malicious.
        # =================================
        if (
            1
            <= destination_port
            <= config.privileged_port_max
        ):
            reasons.append(
                "Destination port is in the privileged range"
            )

        # =================================
        # Dynamic / Private Port
        # =================================
        elif (
            config.dynamic_port_min
            <= destination_port
            <= config.dynamic_port_max
        ):
            reasons.append(
                "Destination port is in the dynamic/private range"
            )

        # =================================
        # High-Risk Port
        #
        # Strong indicator according to the
        # configured high-risk port list.
        # =================================
        if destination_port in high_risk_ports:
            score += 40

            reasons.append(
                "High-risk destination port"
            )

        # =================================
        # Protocol / Port Context
        # =================================
        if port_protocols is None:
            # Unknown protocol profile is
            # Do not add score merely because
            # there is no configured profile.
            if config.unknown_protocol_score > 0:
                score += config.unknown_protocol_score

            reasons.append(
                "No expected protocol profile"
            )

        elif protocol not in port_protocols:
            # Protocol mismatch is meaningful
            # because this destination port has
            # an established expected protocol.
            score += config.protocol_mismatch_score

            expected = ", ".join(
                sorted(port_protocols)
            )

            reasons.append(
                f"Unexpected protocol {protocol} "
                f"for port {destination_port}, "
                f"expected {expected}"
            )

        # =================================
        # Repeated Traffic
        #
        # Supporting evidence.
        # =================================
        if packet_count >= config.min_packets:
            score += 15

            reasons.append(
                "Repeated traffic"
            )

        # =================================
        # Minimum Confidence
        # =================================
        if score < config.min_confidence:
            continue

        # =================================
        # Severity
        # =================================
        if score >= 80:
            severity = "HIGH"

        elif score >= 60:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        # =================================
        # Detection Result
        # =================================
        results.append(
            {
                "detector": "Unusual Port Detection",

                "severity": severity,

                "confidence": round(
                    max(
                        0,
                        min(100, score),
                    )
                ),

                "source": flow["source"],

                "destination": flow["destination"],

                "evidence": {
                    "protocol": protocol,

                    "source_port": flow["source_port"],

                    "source_ports": sorted(
                        flow["source_ports"]
                    ),

                    "destination_port": (
                        destination_port
                    ),

                    "service": service_status,

                    "known_service": known_service,

                    "port_frequency": (
                        port_frequency[
                            destination_port
                        ]
                    ),

                    "total_transport_packets": (
                        total_transport_packets
                    ),

                    "frequency": frequency,

                    "rarity": rarity,

                    "expected_protocols": (
                        sorted(port_protocols)
                        if port_protocols
                        else []
                    ),

                    "packets": packet_count,

                    "reasons": reasons,
                },
            }
        )

    return results
