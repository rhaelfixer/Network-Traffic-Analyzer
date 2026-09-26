from collections import Counter, defaultdict

from config.config import CONFIG


# =================================
# ICMP Flood Detection
# =================================
def detect_icmp_floods(packets):
    config = CONFIG.icmp_flood

    # =================================
    # Traffic Tracking
    # =================================
    traffic = defaultdict(
        lambda: {
            "packets": 0,
            "echo_requests": 0,
            "echo_replies": 0,
            "sources": set(),
            "destinations": Counter(),
            "first_seen": None,
            "last_seen": None,
        }
    )

    # =================================
    # Collect ICMP Traffic
    # =================================
    for packet in packets:
        if not packet.haslayer("ICMP"):
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

        timestamp = float(packet.time)

        # =================================
        # Group by Time Window
        # =================================
        key = int(timestamp // config.window)

        entry = traffic[key]

        # =================================
        # Timestamp Tracking
        # =================================
        if entry["first_seen"] is None:
            entry["first_seen"] = timestamp

        entry["last_seen"] = timestamp

        # =================================
        # Traffic Tracking
        # =================================
        entry["packets"] += 1

        # Track unique sources
        entry["sources"].add(source)

        # Track destination distribution
        entry["destinations"][destination] += 1

        # =================================
        # ICMP Type Tracking
        # =================================
        icmp_type = packet["ICMP"].type

        # ICMP Echo Request
        if icmp_type == 8:
            entry["echo_requests"] += 1

        # ICMP Echo Reply
        elif icmp_type == 0:
            entry["echo_replies"] += 1

    results = []

    # =================================
    # Analyze ICMP Flood Windows
    # =================================
    for data in traffic.values():
        packet_count = data["packets"]

        # ---------------------------------
        # Minimum Packet Threshold
        # ---------------------------------
        if packet_count < config.min_packets:
            continue

        requests = data["echo_requests"]
        replies = data["echo_replies"]

        # =================================
        # Duration
        # =================================
        duration = max(
            data["last_seen"] - data["first_seen"],
            0,
        )

        # =================================
        # Packets Per Second
        # =================================
        if duration > 0:
            packet_rate = packet_count / duration

        else:
            packet_rate = float(packet_count)

        # =================================
        # Request / Reply Ratio
        # =================================
        if replies > 0:
            request_reply_ratio = requests / replies

        else:
            request_reply_ratio = float(requests)

        # =================================
        # Source Diversity
        # =================================
        source_diversity = len(data["sources"])

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

            target_concentration = busiest_target_packets / packet_count

        else:
            busiest_target = None
            busiest_target_packets = 0
            target_concentration = 0.0

        # =================================
        # Burst Score
        # =================================
        if config.min_rate > 0:
            burst_score = min(
                100.0,
                (packet_rate / config.min_rate) * 100,
            )

        else:
            burst_score = 0.0

        # =================================
        # Confidence Score
        # =================================
        score = 0

        # ---------------------------------
        # Packet Rate
        # ---------------------------------
        if packet_rate >= config.min_rate:
            score += 30

        # ---------------------------------
        # Request / Reply Ratio
        # ---------------------------------
        if request_reply_ratio >= config.min_request_reply_ratio:
            score += 20

        # ---------------------------------
        # Source Diversity
        # ---------------------------------
        if source_diversity >= config.min_source_diversity:
            score += 15

        # ---------------------------------
        # Target Concentration
        # ---------------------------------
        if target_concentration >= config.min_target_concentration:
            score += 15

        # ---------------------------------
        # Burst Score
        # ---------------------------------
        if burst_score >= config.min_burst_score:
            score += 20

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
                "detector": "ICMP Flood Detection",
                "severity": severity,
                "confidence": round(
                    max(
                        0,
                        min(100, score),
                    )
                ),
                "source": (
                    next(iter(data["sources"])) if source_diversity == 1 else None
                ),
                "destination": busiest_target,
                "evidence": {
                    "icmp_packets": packet_count,
                    "icmp_packets_per_second": packet_rate,
                    "echo_requests": requests,
                    "echo_replies": replies,
                    "echo_request_reply_ratio": request_reply_ratio,
                    "source_diversity": source_diversity,
                    "target_count": target_count,
                    "target_concentration": target_concentration,
                    "busiest_target": busiest_target,
                    "busiest_target_packets": busiest_target_packets,
                    "destination_distribution": dict(destination_counts),
                    "burst_score": burst_score,
                    "duration": duration,
                    "window": config.window,
                },
            }
        )

    return results
