from collections import Counter, defaultdict

from config.config import CONFIG


# =================================
# Traffic Rate Anomaly Detection
# =================================
def detect_traffic_rate_anomalies(packets):
    config = CONFIG.traffic_rate

    # =================================
    # Traffic Tracking
    # =================================
    traffic = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
            "sources": Counter(),
            "destinations": Counter(),
            "protocols": Counter(),
            "first_seen": None,
            "last_seen": None,
        }
    )

    # =================================
    # Collect Traffic
    # =================================
    for packet in packets:
        # ---------------------------------
        # Get IP addresses
        # ---------------------------------
        if packet.haslayer("IP"):
            source = packet["IP"].src
            destination = packet["IP"].dst

        elif packet.haslayer("IPv6"):
            source = packet["IPv6"].src
            destination = packet["IPv6"].dst

        else:
            continue

        timestamp = float(packet.time)

        # =================================
        # Determine Protocol
        # =================================
        if packet.haslayer("TCP"):
            protocol = "TCP"

        elif packet.haslayer("UDP"):
            protocol = "UDP"

        elif packet.haslayer("ICMP"):
            protocol = "ICMP"

        elif packet.haslayer("ICMPv6"):
            protocol = "ICMPv6"

        else:
            protocol = "OTHER"

        # =================================
        # Group by Time Window
        # =================================
        window = int(timestamp // config.window)

        entry = traffic[window]

        # =================================
        # Timestamp Tracking
        # =================================
        if entry["first_seen"] is None:
            entry["first_seen"] = timestamp

        entry["last_seen"] = timestamp

        # =================================
        # Traffic Statistics
        # =================================
        entry["packets"] += 1
        entry["bytes"] += len(packet)

        # =================================
        # Source Distribution
        # =================================
        entry["sources"][source] += 1

        # =================================
        # Destination Distribution
        # =================================
        entry["destinations"][destination] += 1

        # =================================
        # Protocol Distribution
        # =================================
        entry["protocols"][protocol] += 1

    # =================================
    # No Traffic
    # =================================
    if not traffic:
        return []

    # =================================
    # Capture Baseline
    #
    # The baseline represents the average
    # traffic volume across the populated
    # windows in the current capture.
    # =================================
    packet_counts = [
        data["packets"]
        for data in traffic.values()
    ]

    byte_counts = [
        data["bytes"]
        for data in traffic.values()
    ]

    average_packets = (
        sum(packet_counts) / len(packet_counts)
    )

    average_bytes = (
        sum(byte_counts) / len(byte_counts)
    )

    results = []

    # =================================
    # Analyze Each Traffic Window
    # =================================
    for window, data in traffic.items():
        packet_count = data["packets"]
        byte_count = data["bytes"]

        # =================================
        # Duration
        # =================================
        duration = max(
            data["last_seen"] - data["first_seen"],
            0,
        )

        # =================================
        # Packet Rate
        # =================================
        if duration > 0:
            packets_per_second = (
                packet_count / duration
            )

            bytes_per_second = (
                byte_count / duration
            )

        else:
            packets_per_second = (
                packet_count / config.window
            )

            bytes_per_second = (
                byte_count / config.window
            )

        # =================================
        # Average Packet Size
        # =================================
        if packet_count > 0:
            average_packet_size = (
                byte_count / packet_count
            )

        else:
            average_packet_size = 0.0

        # =================================
        # Capture Baseline Deviation
        #
        # Compare this window against the
        # average traffic volume in the
        # current capture.
        # =================================
        if average_packets > 0:
            packet_baseline_deviation = (
                packet_count / average_packets
            )

        else:
            packet_baseline_deviation = 0.0

        if average_bytes > 0:
            byte_baseline_deviation = (
                byte_count / average_bytes
            )

        else:
            byte_baseline_deviation = 0.0

        # =================================
        # Burst Detection
        #
        # A burst occurs when packet volume
        # reaches the configured burst
        # multiplier relative to the
        # capture baseline.
        # =================================
        burst_detected = (
            packet_baseline_deviation
            >= config.burst_multiplier
        )

        # =================================
        # High Burst Detection
        #
        # High burst is a stronger burst level.
        # It is evaluated separately so that a
        # high burst does not receive both the
        # normal burst and high-burst scores.
        # =================================
        high_burst_detected = (
            packet_baseline_deviation
            >= config.high_burst_multiplier
        )

        # =================================
        # Source Concentration
        # =================================
        source_counts = data["sources"]

        source_count = len(source_counts)

        if packet_count > 0 and source_count > 0:
            (
                busiest_source,
                busiest_source_packets,
            ) = source_counts.most_common(1)[0]

            source_concentration = (
                busiest_source_packets / packet_count
            )

        else:
            busiest_source = None
            busiest_source_packets = 0
            source_concentration = 0.0

        # =================================
        # Destination Concentration
        # =================================
        destination_counts = data["destinations"]

        destination_count = len(destination_counts)

        if packet_count > 0 and destination_count > 0:
            (
                busiest_destination,
                busiest_destination_packets,
            ) = destination_counts.most_common(1)[0]

            destination_concentration = (
                busiest_destination_packets
                / packet_count
            )

        else:
            busiest_destination = None
            busiest_destination_packets = 0
            destination_concentration = 0.0

        # =================================
        # Protocol Distribution
        # =================================
        protocol_counts = data["protocols"]

        protocol_distribution = {}

        if packet_count > 0:
            for protocol, count in protocol_counts.items():
                protocol_distribution[protocol] = (
                    count / packet_count
                )

        # =================================
        # Confidence Score
        # =================================
        score = 0

        # ---------------------------------
        # Packet Rate
        # ---------------------------------
        if (
            packets_per_second
            >= config.min_packets_per_second
        ):
            score += 25

        # ---------------------------------
        # Minimum Packet Volume
        # ---------------------------------
        if packet_count >= config.min_packets:
            score += 15

        # ---------------------------------
        # Burst
        # ---------------------------------
        if high_burst_detected:
            score += 35

        elif burst_detected:
            score += 20

        # ---------------------------------
        # Source Concentration
        # ---------------------------------
        if source_concentration >= 0.80:
            score += 10

        # ---------------------------------
        # Destination Concentration
        # ---------------------------------
        if destination_concentration >= 0.80:
            score += 10

        # ---------------------------------
        # Protocol Activity
        # ---------------------------------
        if len(protocol_counts) >= 2:
            score += 5

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
                "detector": "Traffic Rate Anomaly",
                "severity": severity,
                "confidence": round(
                    max(
                        0,
                        min(100, score),
                    )
                ),
                "source": busiest_source,
                "destination": busiest_destination,
                "evidence": {
                    # -------------------------
                    # Traffic Volume
                    # -------------------------
                    "packets": packet_count,
                    "bytes": byte_count,

                    # -------------------------
                    # Traffic Rates
                    # -------------------------
                    "packets_per_second": (
                        packets_per_second
                    ),
                    "bytes_per_second": (
                        bytes_per_second
                    ),

                    # -------------------------
                    # Packet Characteristics
                    # -------------------------
                    "average_packet_size": (
                        average_packet_size
                    ),

                    # -------------------------
                    # Capture Baseline
                    # -------------------------
                    "baseline_packets": (
                        average_packets
                    ),
                    "baseline_bytes": (
                        average_bytes
                    ),
                    "packet_baseline_deviation": (
                        packet_baseline_deviation
                    ),
                    "byte_baseline_deviation": (
                        byte_baseline_deviation
                    ),

                    # -------------------------
                    # Burst Detection
                    # -------------------------
                    "burst_detected": (
                        burst_detected
                    ),
                    "high_burst_detected": (
                        high_burst_detected
                    ),

                    # -------------------------
                    # Source Concentration
                    # -------------------------
                    "source_count": source_count,
                    "busiest_source": (
                        busiest_source
                    ),
                    "busiest_source_packets": (
                        busiest_source_packets
                    ),
                    "source_concentration": (
                        source_concentration
                    ),
                    "source_distribution": (
                        dict(source_counts)
                    ),

                    # -------------------------
                    # Destination Concentration
                    # -------------------------
                    "destination_count": (
                        destination_count
                    ),
                    "busiest_destination": (
                        busiest_destination
                    ),
                    "busiest_destination_packets": (
                        busiest_destination_packets
                    ),
                    "destination_concentration": (
                        destination_concentration
                    ),
                    "destination_distribution": (
                        dict(destination_counts)
                    ),

                    # -------------------------
                    # Protocol Distribution
                    # -------------------------
                    "protocol_distribution": (
                        protocol_distribution
                    ),

                    # -------------------------
                    # Window
                    # -------------------------
                    "window": config.window,
                    "duration": duration,
                },
            }
        )

    return results
