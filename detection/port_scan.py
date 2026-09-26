from collections import defaultdict

from config.config import CONFIG


# =================================
# Port Scan Detection
# =================================
def detect_port_scans(packets):
    config = CONFIG.port_scan

    scans = defaultdict(
        lambda: {
            "targets": defaultdict(
                lambda: {
                    "destination_ports": set(),
                    "source_ports": set(),
                    "syn": 0,
                    "syn_ack": 0,
                    "ack": 0,
                    "first_seen": None,
                    "last_seen": None,
                }
            ),
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

        source_port = int(packet["TCP"].sport)
        destination_port = int(packet["TCP"].dport)

        flags = packet["TCP"].flags
        timestamp = float(packet.time)

        # =================================
        # Group by Source and Time Window
        # =================================
        key = (
            source,
            int(timestamp // config.window),
        )

        target = scans[key]["targets"][destination]

        # ---------------------------------
        # Timestamp Tracking
        # ---------------------------------
        if target["first_seen"] is None:
            target["first_seen"] = timestamp

        target["last_seen"] = timestamp

        # ---------------------------------
        # Port Tracking
        # ---------------------------------
        target["destination_ports"].add(destination_port)

        target["source_ports"].add(source_port)

        # ---------------------------------
        # TCP Flag Tracking
        # ---------------------------------
        if "S" in flags and "A" not in flags:
            target["syn"] += 1

        elif "S" in flags and "A" in flags:
            target["syn_ack"] += 1

        elif "A" in flags:
            target["ack"] += 1

    results = []

    # =================================
    # Analyze Each Scan Window
    # =================================
    for (
        source,
        window,
    ), scan_data in scans.items():
        targets = scan_data["targets"]

        if not targets:
            continue

        # =================================
        # Total Unique Ports
        # =================================
        total_unique_ports = sum(
            len(target["destination_ports"]) for target in targets.values()
        )

        # ---------------------------------
        # Find Primary Target
        # ---------------------------------
        primary_target = max(
            targets.items(),
            key=lambda item: len(item[1]["destination_ports"]),
        )

        destination, data = primary_target

        unique_destination_ports = len(data["destination_ports"])

        unique_source_ports = len(data["source_ports"])

        syn_packets = data["syn"]
        syn_ack_packets = data["syn_ack"]
        ack_packets = data["ack"]

        # =================================
        # SYN Requirement
        # =================================
        if syn_packets == 0:
            continue

        # =================================
        # Duration
        # =================================
        duration = max(
            data["last_seen"] - data["first_seen"],
            0,
        )

        # =================================
        # Port Scan Rate
        # =================================
        if duration == 0:
            scan_rate = float(unique_destination_ports)

        else:
            scan_rate = unique_destination_ports / duration

        # =================================
        # SYN / SYN-ACK Response Ratio
        # =================================
        response_ratio = syn_ack_packets / syn_packets

        # =================================
        # Connection Completion Ratio
        # =================================
        completion_ratio = ack_packets / syn_packets

        # =================================
        # Failure Ratio
        # =================================
        failure_ratio = max(
            0,
            1 - completion_ratio,
        )

        # =================================
        # Sequential Port Behavior
        # =================================
        ports = sorted(data["destination_ports"])

        sequential_pairs = 0

        for index in range(1, len(ports)):
            if ports[index] == ports[index - 1] + 1:
                sequential_pairs += 1

        if len(ports) > 1:
            sequential_ratio = sequential_pairs / (len(ports) - 1)

        else:
            sequential_ratio = 0

        # =================================
        # Target Concentration
        # =================================
        if total_unique_ports > 0:
            target_concentration = unique_destination_ports / total_unique_ports

        else:
            target_concentration = 0

        # =================================
        # Target Count
        # =================================
        target_count = len(targets)

        # =================================
        # Confidence Score
        # =================================
        score = 0

        # ---------------------------------
        # Unique Destination Ports
        # ---------------------------------
        if unique_destination_ports >= config.min_unique_ports:
            score += 30

        # ---------------------------------
        # Port Scan Rate
        # ---------------------------------
        if scan_rate >= config.min_rate:
            score += 15

        # ---------------------------------
        # Low Response Ratio
        # ---------------------------------
        if response_ratio < config.max_response_ratio:
            score += 15

        # ---------------------------------
        # High Failure Ratio
        # ---------------------------------
        if failure_ratio >= config.min_failure_ratio:
            score += 15

        # ---------------------------------
        # Sequential Behavior
        # ---------------------------------
        if sequential_ratio >= config.min_sequential_ratio:
            score += 10

        # ---------------------------------
        # Target Concentration
        # ---------------------------------
        if target_concentration >= config.min_target_concentration:
            score += 10

        # ---------------------------------
        # Source Port Diversity
        # ---------------------------------
        if unique_source_ports >= config.min_unique_ports:
            score += 5

        # =================================
        # Minimum Confidence
        # =================================
        if score < config.min_confidence:
            continue

        # =================================
        # Severity
        # =================================
        severity = "HIGH" if score >= 80 else "MEDIUM"

        # =================================
        # Detection Result
        # =================================
        results.append(
            {
                "detector": "Port Scan Detection",
                "severity": severity,
                "confidence": round(
                    max(
                        0,
                        min(100, score),
                    )
                ),
                "source": source,
                "destination": destination,
                "evidence": {
                    "unique_destination_ports": unique_destination_ports,
                    "unique_source_ports": unique_source_ports,
                    "port_scan_rate": scan_rate,
                    "syn_packets": syn_packets,
                    "syn_ack_packets": syn_ack_packets,
                    "ack_packets": ack_packets,
                    "response_ratio": response_ratio,
                    "connection_failure_ratio": failure_ratio,
                    "sequential_port_ratio": sequential_ratio,
                    "target_count": target_count,
                    "target_concentration": target_concentration,
                    "total_unique_ports": total_unique_ports,
                    "duration": duration,
                    "window": config.window,
                },
            }
        )

    return results
