from collections import defaultdict

from config.config import CONFIG


# =================================
# ARP Anomaly Detection
# =================================
def detect_arp_anomalies(packets):
    config = CONFIG.arp_anomaly

    # =================================
    # Traffic Tracking
    # =================================
    ip_to_macs = defaultdict(set)
    mac_to_ips = defaultdict(set)

    arp_requests = defaultdict(int)
    arp_replies = defaultdict(int)

    gratuitous_arp = defaultdict(int)

    # Track broadcasts by source MAC and
    # time window.
    broadcast_counts = defaultdict(int)

    first_seen = {}
    last_seen = {}

    # =================================
    # Collect ARP Traffic
    # =================================
    for packet in packets:
        if not packet.haslayer("ARP"):
            continue

        arp = packet["ARP"]

        source_ip = arp.psrc
        source_mac = arp.hwsrc
        target_ip = arp.pdst

        timestamp = float(packet.time)

        window = int(timestamp // config.broadcast_window)

        # =================================
        # IP -> MAC Mapping
        # =================================
        ip_to_macs[source_ip].add(source_mac)

        # =================================
        # MAC -> IP Mapping
        # =================================
        mac_to_ips[source_mac].add(source_ip)

        # =================================
        # ARP Request / Reply
        # =================================
        if arp.op == 1:
            arp_requests[source_mac] += 1

        elif arp.op == 2:
            arp_replies[source_mac] += 1

        # =================================
        # Gratuitous ARP
        # =================================
        #
        # A common gratuitous ARP pattern is:
        #
        # sender IP == target IP
        #
        if source_ip == target_ip:
            gratuitous_arp[source_mac] += 1

        # =================================
        # Broadcast Tracking
        # =================================
        if (
            packet.haslayer("Ether")
            and packet["Ether"].dst.lower() == "ff:ff:ff:ff:ff:ff"
        ):
            key = (
                source_mac,
                window,
            )

            broadcast_counts[key] += 1

            if key not in first_seen:
                first_seen[key] = timestamp

            last_seen[key] = timestamp

    results = []

    # =================================
    # IP -> Multiple MAC Addresses
    # =================================
    for ip, macs in ip_to_macs.items():
        if len(macs) < config.min_mapping_conflicts + 1:
            continue

        results.append(
            {
                "detector": "ARP Anomaly Detection",
                "severity": "HIGH",
                "confidence": 90,
                "source": ip,
                "destination": None,
                "evidence": {
                    "reason": ("IP address mapped to multiple MAC addresses"),
                    "ip_address": ip,
                    "mac_addresses": sorted(macs),
                    "mac_count": len(macs),
                },
            }
        )

    # =================================
    # MAC -> Multiple IP Addresses
    # =================================
    for mac, ips in mac_to_ips.items():
        if len(ips) < config.min_ips_per_mac:
            continue

        results.append(
            {
                "detector": "ARP Anomaly Detection",
                "severity": "MEDIUM",
                "confidence": 70,
                "source": mac,
                "destination": None,
                "evidence": {
                    "reason": ("MAC address associated with multiple IP addresses"),
                    "mac_address": mac,
                    "ip_addresses": sorted(ips),
                    "ip_count": len(ips),
                },
            }
        )

    # =================================
    # Gratuitous ARP
    # =================================
    for mac, count in gratuitous_arp.items():
        if count < config.min_gratuitous_packets:
            continue

        results.append(
            {
                "detector": "ARP Anomaly Detection",
                "severity": "MEDIUM",
                "confidence": 60,
                "source": mac,
                "destination": None,
                "evidence": {
                    "reason": "Gratuitous ARP detected",
                    "source_mac": mac,
                    "gratuitous_arp_packets": count,
                },
            }
        )

    # =================================
    # Request / Reply Imbalance
    # =================================
    all_macs = set(arp_requests) | set(arp_replies)

    for mac in all_macs:
        requests = arp_requests[mac]
        replies = arp_replies[mac]

        if requests == 0:
            continue

        if replies > 0:
            ratio = requests / replies

        else:
            ratio = float(requests)

        if ratio < config.request_reply_imbalance:
            continue

        results.append(
            {
                "detector": "ARP Anomaly Detection",
                "severity": "MEDIUM",
                "confidence": 65,
                "source": mac,
                "destination": None,
                "evidence": {
                    "reason": "ARP request/reply imbalance",
                    "source_mac": mac,
                    "requests": requests,
                    "replies": replies,
                    "request_reply_ratio": ratio,
                },
            }
        )

    # =================================
    # Broadcast Rate
    # =================================
    for (
        mac,
        window,
    ), count in broadcast_counts.items():
        duration = max(
            last_seen[(mac, window)] - first_seen[(mac, window)],
            0,
        )

        # If all broadcasts have the same
        # timestamp, use the configured
        # window as the rate interval.
        if duration > 0:
            broadcast_rate = count / duration

        else:
            broadcast_rate = count / config.broadcast_window

        if broadcast_rate < config.min_broadcast_rate:
            continue

        results.append(
            {
                "detector": "ARP Anomaly Detection",
                "severity": "HIGH",
                "confidence": 85,
                "source": mac,
                "destination": "ff:ff:ff:ff:ff:ff",
                "evidence": {
                    "reason": "High ARP broadcast rate",
                    "source_mac": mac,
                    "broadcast_packets": count,
                    "broadcast_rate": broadcast_rate,
                    "window": config.broadcast_window,
                },
            }
        )

    return results
