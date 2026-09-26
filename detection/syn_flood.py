from collections import Counter, defaultdict

from config.config import CONFIG


# =================================
# SYN Flood Detection
# =================================
def detect_syn_floods(packets):
    config = CONFIG.syn_flood

    # =================================
    # Traffic Tracking
    # =================================
    flows = defaultdict(
        lambda: {
            "syn": 0,
            "syn_ack": 0,
            "ack": 0,
            "completed": 0,
            "source_ports": set(),
            "destination_ports": set(),
            "sources": set(),
            "destinations": Counter(),
            "first_seen": None,
            "last_seen": None,

            # Track individual TCP handshakes
            "pending_syn": {},
            "responded_syn": set(),
        }
    )

    # =================================
    # Collect TCP Traffic
    # =================================
    for packet in packets:
        if not packet.haslayer("TCP"):
            continue

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

        tcp = packet["TCP"]

        source_port = int(tcp.sport)
        destination_port = int(tcp.dport)

        flags = tcp.flags
        timestamp = float(packet.time)

        # =================================
        # Group by Time Window
        # =================================
        key = int(timestamp // config.window)

        entry = flows[key]

        # =================================
        # Timestamp Tracking
        # =================================
        if entry["first_seen"] is None:
            entry["first_seen"] = timestamp

        entry["last_seen"] = timestamp

        # =================================
        # Traffic Tracking
        # =================================
        entry["sources"].add(source)

        entry["source_ports"].add(source_port)

        entry["destination_ports"].add(destination_port)

        entry["destinations"][destination] += 1

        # =================================
        # TCP Flag Detection
        # =================================
        syn_flag = bool(flags & 0x02)
        ack_flag = bool(flags & 0x10)

        # =================================
        # SYN
        # =================================
        if syn_flag and not ack_flag:
            entry["syn"] += 1

            # TCP connection identifier
            connection = (
                source,
                source_port,
                destination,
                destination_port,
            )

            entry["pending_syn"][connection] = timestamp

        # =================================
        # SYN-ACK
        # =================================
        elif syn_flag and ack_flag:
            entry["syn_ack"] += 1

            # Reverse the SYN direction
            connection = (
                destination,
                destination_port,
                source,
                source_port,
            )

            if connection in entry["pending_syn"]:
                entry["responded_syn"].add(connection)

        # =================================
        # ACK
        # =================================
        elif ack_flag and not syn_flag:
            connection = (
                destination,
                destination_port,
                source,
                source_port,
            )

            # Only count the ACK as completion if
            # we previously observed a SYN-ACK
            if connection in entry["responded_syn"]:
                entry["ack"] += 1
                entry["completed"] += 1

                # Remove it so duplicate ACKs
                # cannot inflate completion count
                entry["responded_syn"].discard(connection)
                entry["pending_syn"].pop(connection, None)

    results = []

    # =================================
    # Analyze SYN Flood Windows
    # =================================
    for data in flows.values():

        syn_packets = data["syn"]

        # ---------------------------------
        # Minimum SYN threshold
        # ---------------------------------
        if syn_packets < config.min_packets:
            continue

        syn_ack_packets = data["syn_ack"]

        # =================================
        # Completed Handshakes
        # =================================
        completed_handshakes = data["completed"]

        # =================================
        # Duration
        # =================================
        duration = max(
            data["last_seen"] - data["first_seen"],
            0,
        )

        # =================================
        # SYN Rate
        # =================================
        if duration > 0:
            syn_rate = syn_packets / duration

        else:
            syn_rate = float(syn_packets)

        # =================================
        # SYN / SYN-ACK Ratio
        # =================================
        syn_ack_ratio = (
            syn_ack_packets / syn_packets
        )

        # =================================
        # Completion Ratio
        # =================================
        completion_ratio = (
            completed_handshakes / syn_packets
        )

        # =================================
        # Half-Open Ratio
        # =================================
        half_open_ratio = max(
            0,
            1 - completion_ratio,
        )

        # =================================
        # Source Diversity
        # =================================
        source_diversity = len(
            data["sources"]
        )

        # =================================
        # Target Concentration
        # =================================
        destination_counts = data["destinations"]

        target_count = len(destination_counts)

        if target_count > 0:
            (
                busiest_target,
                busiest_target_packets,
            ) = destination_counts.most_common(1)[0]

            # Only SYN packets should determine
            # SYN target concentration
            target_concentration = (
                busiest_target_packets / syn_packets
            )

        else:
            busiest_target = None
            busiest_target_packets = 0
            target_concentration = 0.0

        # =================================
        # Confidence Score
        # =================================
        score = 0

        # ---------------------------------
        # SYN Rate
        # ---------------------------------
        if syn_rate >= config.min_rate:
            score += 25

        # ---------------------------------
        # SYN / SYN-ACK Ratio
        # ---------------------------------
        if syn_ack_ratio <= config.max_syn_ack_ratio:
            score += 20

        # ---------------------------------
        # Completion Ratio
        # ---------------------------------
        if completion_ratio <= config.max_completion_ratio:
            score += 25

        # ---------------------------------
        # Half-Open Ratio
        # ---------------------------------
        if half_open_ratio >= config.min_half_open_ratio:
            score += 15

        # ---------------------------------
        # Source Diversity
        # ---------------------------------
        if source_diversity >= config.min_source_diversity:
            score += 10

        # ---------------------------------
        # Target Concentration
        # ---------------------------------
        if target_concentration >= 0.90:
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

        else:
            severity = "MEDIUM"

        # =================================
        # Detection Result
        # =================================
        results.append(
            {
                "detector": "SYN Flood Detection",
                "severity": severity,
                "confidence": round(
                    max(
                        0,
                        min(100, score),
                    )
                ),
                "destination": busiest_target,
                "evidence": {
                    "syn_packets": syn_packets,
                    "syn_rate": syn_rate,
                    "syn_ack_packets": syn_ack_packets,
                    "syn_ack_ratio": syn_ack_ratio,

                    # Actual completed handshakes
                    "completed_handshakes": (
                        completed_handshakes
                    ),

                    "completion_ratio": (
                        completion_ratio
                    ),

                    "half_open_ratio": (
                        half_open_ratio
                    ),

                    "source_diversity": (
                        source_diversity
                    ),

                    "source_ports": len(
                        data["source_ports"]
                    ),

                    "destination_ports": len(
                        data["destination_ports"]
                    ),

                    "target_count": (
                        target_count
                    ),

                    "target_concentration": (
                        target_concentration
                    ),

                    "busiest_target": (
                        busiest_target
                    ),

                    "busiest_target_packets": (
                        busiest_target_packets
                    ),

                    "destination_distribution": (
                        dict(destination_counts)
                    ),

                    "window": config.window,
                    "duration": duration,
                },
            }
        )

    return results
