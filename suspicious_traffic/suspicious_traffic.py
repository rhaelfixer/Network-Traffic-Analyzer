import os

from detection.detection import detect
from utils.menu_display import MENU_WIDTH
from utils.pcap_loader import (
    load_capture,
    select_capture_file,
)

LABEL_WIDTH = 35
INDENT = 2


# =================================
# Suspicious Traffic Detection
# =================================
def suspicious_traffic(filepath=None, wait_for_input=True):

    if filepath is None:
        filepath = select_capture_file()

        if filepath is None:
            return

    packets = load_capture(filepath)

    if packets is None:
        return

    print()
    print("[*] Analyzing suspicious traffic...")
    print("[*] Running detection engines...")

    results = detect(packets)

    print("[*] Analysis completed.")

    display_detection_results(
        filepath,
        results,
    )

    if wait_for_input:
        print()
        input("Press ENTER to return to the Main Menu...")
        print()


# =================================
# Display Detection Results
# =================================
def display_detection_results(filepath, results):
    filename = os.path.basename(filepath)

    print()
    print("=" * MENU_WIDTH)
    print("SUSPICIOUS TRAFFIC DETECTION".center(MENU_WIDTH))
    print("=" * MENU_WIDTH)
    print()

    print_field("Capture File:", f"{filename}")
    print()

    display_port_scans(results["port_scan"])
    display_unusual_ports(results["unusual_port"])
    display_syn_floods(results["syn_flood"])
    display_icmp_floods(results["icmp_flood"])
    display_arp_anomalies(results["arp_anomaly"])
    display_dns_anomalies(results["dns_anomaly"])
    display_traffic_rates(results["traffic_rate"])
    print()

    print("=" * MENU_WIDTH)


# =================================
# Common Helpers
# =================================
def print_no_activity():
    print()
    print("No suspicious activity detected.")

def print_alert_header(alert_name, result, indent=INDENT):
    print()
    print(f"[ALERT] {alert_name}")

    if result.get("source"):
        print_field(
            "Source:",
            result["source"],
            indent=indent
        )

    if result.get("destination"):
        print_field(
            "Target:",
            result["destination"],
            indent=indent
        )

    print_field(
        "Severity:",
        result["severity"],
        indent=indent
    )

    print_field(
        "Confidence:",
        f"{result['confidence']}%",
        indent=indent
    )

def print_field(label, value, indent=INDENT, prefix=""):
    print(f"{' ' * indent}{prefix}{label:<{LABEL_WIDTH}}{value}")


# =================================
# Port Scan Detection
# =================================
def display_port_scans(results):
    print("-" * MENU_WIDTH)
    print("PORT SCAN DETECTION")
    print("-" * MENU_WIDTH)

    if not results:
        print_no_activity()
        return

    for result in results:
        evidence = result["evidence"]

        print_alert_header(
            "Possible Port Scan",
            result,
        )

        print_field(
            "Unique Dest Ports:",
            evidence["unique_destination_ports"],
        )

        print_field("Total Unique Ports:", evidence["total_unique_ports"])

        print_field("Unique Source Ports:", evidence["unique_source_ports"])

        print_field("Target Count:", evidence["target_count"])

        print_field(
            "Target Concentration:",
            f"{evidence['target_concentration']:.2%}",
        )

        print_field("SYN Packets:", evidence["syn_packets"])

        print_field("SYN-ACK Packets:", evidence["syn_ack_packets"])

        print_field("ACK Packets:", evidence["ack_packets"])

        print_field("Scan Rate:", f"{evidence['port_scan_rate']:.2f}/sec")

        print_field(
            "SYN/ACK Response Ratio:",
            f"{evidence['response_ratio']:.2%}",
        )

        print_field(
            "Connection Failure Ratio:",
            f"{evidence['connection_failure_ratio']:.2%}",
        )

        print_field(
            "Sequential Port Ratio:",
            f"{evidence['sequential_port_ratio']:.2%}",
        )

        print_field("Duration:", f"{evidence['duration']:.2f} seconds")

        print_field("Window:", f"{evidence['window']} seconds")


# =================================
# Unusual Port Detection
# =================================
def display_unusual_ports(results):
    print()
    print("-" * MENU_WIDTH)
    print("UNUSUAL PORT DETECTION")
    print("-" * MENU_WIDTH)

    if not results:
        print_no_activity()
        return

    # =================================
    # Aggregate Related Results
    # =================================
    groups = {}

    for result in results:
        evidence = result["evidence"]

        source = result.get("source")
        destination = result.get("destination")

        # ---------------------------------
        # Group both traffic directions
        # into the same host pair
        # ---------------------------------
        host_pair = tuple(
            sorted(
                filter(
                    None,
                    [source, destination],
                )
            )
        )

        if host_pair not in groups:
            groups[host_pair] = {
                "results": [],
                "ports": set(),
                "flows": 0,
                "packets": 0,
                "reasons": set(),
                "severities": [],
                "confidences": [],
            }

        group = groups[host_pair]

        group["results"].append(result)
        group["ports"].add(evidence["destination_port"])
        group["flows"] += 1
        group["packets"] += evidence["packets"]

        group["severities"].append(result["severity"])
        group["confidences"].append(result["confidence"])

        for reason in evidence["reasons"]:
            group["reasons"].add(reason)

    # =================================
    # Display Aggregated Results
    # =================================
    for host_pair, group in groups.items():
        # =================================
        # Determine Severity
        # =================================
        if "HIGH" in group["severities"]:
            severity = "HIGH"

        elif "MEDIUM" in group["severities"]:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        # =================================
        # Determine Confidence
        # =================================
        confidence = max(group["confidences"])

        # =================================
        # Determine Hosts
        # =================================
        if len(host_pair) == 2:
            source, destination = host_pair

        elif len(host_pair) == 1:
            source = host_pair[0]
            destination = None

        else:
            source = None
            destination = None

        # =================================
        # Alert Header
        # =================================
        print()
        print("[ALERT] Unusual Port Activity")

        if source:
            print_field("Source:", source)

        if destination:
            print_field("Target:", destination)

        print_field("Severity:", severity)

        print_field("Confidence:", f"{confidence}%")

        # =================================
        # Port Summary
        # =================================
        suspicious_ports = sorted(group["ports"])
        print_field("Suspicious Ports:", f"{len(suspicious_ports)}")

        # ---------------------------------
        # Port Range
        # ---------------------------------
        if suspicious_ports:
            print_field(
                "Port Range:",
                f"{suspicious_ports[0]} - {suspicious_ports[-1]}",
            )

        # =================================
        # Traffic Summary
        # =================================
        print_field("Suspicious Flows:", f"{group['flows']}")

        print_field("Total Packets:", f"{group['packets']}")

        print()

        # =================================
        # Primary Indicators
        # =================================
        print("Primary Indicators:")

        for reason in sorted(group["reasons"]):
            print_field(
                reason,
                "",
                prefix="- ",
            )


# =================================
# SYN Flood Detection
# =================================
def display_syn_floods(results):
    print()
    print("-" * MENU_WIDTH)
    print("SYN FLOOD DETECTION")
    print("-" * MENU_WIDTH)

    if not results:
        print_no_activity()
        return

    for result in results:
        evidence = result["evidence"]

        print_alert_header(
            "Possible SYN Flood",
            result,
        )

        print_field("SYN Packets:", f"{evidence['syn_packets']}")

        print_field("SYN Rate:", f"{evidence['syn_rate']:.2f}/sec")

        print_field("SYN-ACK Packets:", f"{evidence['syn_ack_packets']}")

        print_field("SYN/SYN-ACK Ratio:", f"{evidence['syn_ack_ratio']:.2%}")

        # =================================
        # Completed Handshakes
        # =================================
        print_field("Completed Handshakes:", f"{evidence['completed_handshakes']}")

        print_field("Completion Ratio:", f"{evidence['completion_ratio']:.2%}")

        print_field("Half-Open Ratio:", f"{evidence['half_open_ratio']:.2%}")

        print_field("Source Diversity:", f"{evidence['source_diversity']}")

        print_field("Source Ports:", f"{evidence['source_ports']}")

        print_field("Destination Ports:", f"{evidence['destination_ports']}")

        print_field("Target Count:", f"{evidence['target_count']}")

        print_field("Target Concentration:", f"{evidence['target_concentration']:.2%}")

        print_field("Busiest Target:", f"{evidence['busiest_target']}")

        print_field("Target SYN Packets:", f"{evidence['busiest_target_packets']}")

        print_field("Duration:", f"{evidence['duration']:.2f} seconds")

        print_field("Window:", f"{evidence['window']} seconds")

        print()

        # =================================
        # Destination Distribution
        # =================================
        print("Destination Distribution:")

        for destination, count in sorted(
            evidence["destination_distribution"].items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            print_field(
                destination,
                f"{count} packets"
            )


# =================================
# ICMP Flood Detection
# =================================
def display_icmp_floods(results):
    print()
    print("-" * MENU_WIDTH)
    print("ICMP FLOOD DETECTION")
    print("-" * MENU_WIDTH)

    if not results:
        print_no_activity()
        return

    for result in results:
        evidence = result["evidence"]

        print_alert_header(
            "Possible ICMP Flood",
            result,
        )

        print_field("ICMP Packets:", f"{evidence['icmp_packets']}")

        print_field("Packets/sec:", f"{evidence['icmp_packets_per_second']:.2f}")

        print_field("Echo Requests:", f"{evidence['echo_requests']}")

        print_field("Echo Replies:", f"{evidence['echo_replies']}")

        print_field(
            "Request/Reply Ratio:", f"{evidence['echo_request_reply_ratio']:.2f}"
        )

        print_field("Source Diversity:", f"{evidence['source_diversity']}")

        print_field("Target Count:", f"{evidence['target_count']}")

        print_field("Target Concentration:", f"{evidence['target_concentration']:.2%}")

        print_field("Busiest Target:", f"{evidence['busiest_target']}")

        print_field("Target Packets:", f"{evidence['busiest_target_packets']}")

        print_field("Burst Score:", f"{evidence['burst_score']:.2f}")

        print_field("Duration:", f"{evidence['duration']:.2f} seconds")

        print_field("Window:", f"{evidence['window']} seconds")

        print()

        print("Destination Distribution:")

        for destination, count in sorted(
            evidence["destination_distribution"].items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            print_field(
                destination,
                f"{count} packets"
            )

        print()


# =================================
# ARP Anomaly Detection
# =================================
def display_arp_anomalies(results):
    print()
    print("-" * MENU_WIDTH)
    print("ARP ANOMALY DETECTION")
    print("-" * MENU_WIDTH)

    if not results:
        print_no_activity()
        return

    for result in results:
        evidence = result["evidence"]

        print_alert_header(
            evidence["reason"],
            result
        )

        # =================================
        # IP -> Multiple MAC Addresses
        # =================================
        if "ip_address" in evidence:
            print_field(
                "IP Address:",
                f"{evidence['ip_address']}"
            )

            print_field(
                "MAC Count:",
                f"{evidence['mac_count']}"
            )

            print()

            print("MAC Addresses:")
            for mac in evidence["mac_addresses"]:
                print_field(
                    mac,
                    "",
                    prefix="- ",
                )

        # =================================
        # MAC -> Multiple IP Addresses
        # =================================
        elif "mac_address" in evidence:
            print_field(
                "MAC Address:",
                f"{evidence['mac_address']}"
            )

            print_field(
                "IP Count:",
                f"{evidence['ip_count']}"
            )

            print()

            print("IP Addresses:")
            for ip in evidence["ip_addresses"]:
                print_field(
                    ip,
                    "",
                    prefix="- ",
                )

        # =================================
        # Gratuitous ARP
        # =================================
        elif "gratuitous_arp_packets" in evidence:
            print_field(
                "Source MAC:",
                f"{evidence['source_mac']}"
            )

            print_field(
                "Gratuitous ARP:",
                f"{evidence['gratuitous_arp_packets']} packets"
            )

        # =================================
        # Request / Reply Imbalance
        # =================================
        elif "request_reply_ratio" in evidence:
            print_field(
                "Source MAC:",
                f"{evidence['source_mac']}"
            )

            print_field(
                "ARP Requests:",
                f"{evidence['requests']}"
            )

            print_field(
                "ARP Replies:",
                f"{evidence['replies']}"
            )

            print_field(
                "Request/Reply Ratio:",
                f"{evidence['request_reply_ratio']:.2f}"
            )

        # =================================
        # Broadcast Rate
        # =================================
        elif "broadcast_rate" in evidence:
            print_field(
                "Source MAC:",
                f"{evidence['source_mac']}"
            )

            print_field(
                "Broadcast Packets:",
                f"{evidence['broadcast_packets']}"
            )

            print_field(
                "Broadcast Rate:",
                f"{evidence['broadcast_rate']:.2f}/sec"
            )

            print_field(
                "Window:",
                f"{evidence['window']} seconds"
            )


# =================================
# DNS Anomaly Detection
# =================================
def display_dns_anomalies(results):
    print()
    print("-" * MENU_WIDTH)
    print("DNS ANOMALY DETECTION")
    print("-" * MENU_WIDTH)

    if not results:
        print_no_activity()
        return

    for result in results:
        evidence = result["evidence"]

        print_alert_header(
            "Possible DNS Anomaly",
            result
        )

        print()

        # =================================
        # DNS Traffic Statistics
        # =================================
        print("DNS Traffic:")

        print_field(
            "DNS Packets:",
            f"{evidence.get('dns_packets', 0)}"
        )

        print_field(
            "DNS Queries:",
            f"{evidence.get('dns_queries', 0)}"
        )

        print_field(
            "DNS Responses:",
            f"{evidence.get('dns_responses', 0)}"
        )

        print_field(
            "DNS Traffic Rate:",
            f"{evidence.get('dns_rate', 0.0):.2f}/sec"
        )

        print_field(
            "Query Rate:",
            f"{evidence.get('query_rate', 0.0):.2f}/sec"
        )

        print_field(
            "Duration:",
            f"{evidence.get('duration', 0.0):.2f} seconds"
        )

        print_field(
            "Window:",
            f"{evidence.get('window', 0)} seconds"
        )

        print()

        # =================================
        # Domain Statistics
        # =================================
        print("Domain Statistics:")

        print_field(
            "Unique Domains:",
            f"{evidence.get('unique_domains', 0)}"
        )

        print_field(
            "Unique Domain Ratio:",
            f"{evidence.get('unique_domain_ratio', 0.0):.2%}"
        )

        print_field(
            "Average Domain Length:",
            f"{evidence.get('average_domain_length', 0.0):.2f}"
        )

        print_field(
            "Maximum Domain Length:",
            f"{evidence.get('maximum_domain_length', 0)}"
        )

        print_field(
            "Average Label Length:",
            f"{evidence.get('average_label_length', 0.0):.2f}"
        )

        print_field(
            "Maximum Label Length:",
            f"{evidence.get('maximum_label_length', 0)}"
        )

        print_field(
            "Digit Ratio:",
            f"{evidence.get('digit_ratio', 0.0):.2%}"
        )

        print()

        # =================================
        # NXDOMAIN Statistics
        # =================================
        print("NXDOMAIN Statistics:")

        print_field(
            "NXDOMAIN Responses:",
            f"{evidence.get('nxdomain', 0)}"
        )

        print_field(
            "NXDOMAIN Ratio:",
            f"{evidence.get('nxdomain_ratio', 0.0):.2%}"
        )

        print()

        # =================================
        # Query Types
        # =================================
        print("Query Types:")

        query_types = evidence.get("query_types", {})

        if query_types:
            for query_type, count in sorted(
                query_types.items(),
                key=lambda item: item[1],
                reverse=True,
            ):
                print_field(
                    query_type,
                    f"{count} queries"
                )
        else:
            print_field(
                "None",
                ""
            )

        print_field(
            "Query Type Count:",
            f"{evidence.get('query_type_count', 0)}"
        )

        print()

        # =================================
        # Advanced Domain Entropy
        # =================================
        print("Advanced Domain Entropy:")

        print_field(
            "Domain Frequency Entropy:",
            f"{evidence.get('domain_frequency_entropy', 0.0):.2f}"
        )

        print_field(
            "Average Character Entropy:",
            f"{evidence.get('average_character_entropy', 0.0):.2f}"
        )

        print_field(
            "Maximum Character Entropy:",
            f"{evidence.get('maximum_character_entropy', 0.0):.2f}"
        )

        print_field(
            "Average Label Entropy:",
            f"{evidence.get('average_label_entropy', 0.0):.2f}"
        )

        print_field(
            "Maximum Label Entropy:",
            f"{evidence.get('maximum_label_entropy', 0.0):.2f}"
        )

        print()

        # =================================
        # Source Concentration
        # =================================
        print("Source Concentration:")

        print_field(
            "Source Count:",
            f"{evidence.get('source_count', 0)}"
        )

        print_field(
            "Busiest Source:",
            f"{evidence.get('busiest_source', 'Unknown')}"
        )

        print_field(
            "Source Packets:",
            f"{evidence.get('busiest_source_packets', 0)}"
        )

        print_field(
            "Source Concentration:",
            f"{evidence.get('source_concentration', 0.0):.2%}"
        )

        print()

        # =================================
        # DNS Server Concentration
        # =================================
        print("DNS Server Concentration:")

        print_field(
            "DNS Server Count:",
            f"{evidence.get('destination_count', 0)}"
        )

        print_field(
            "Busiest DNS Server:",
            evidence.get("busiest_destination", "Unknown")
        )

        print_field(
            "Server Packets:",
            evidence.get("busiest_destination_packets", 0)
        )

        print_field(
            "Server Concentration:",
            f"{evidence.get('destination_concentration', 0.0):.2%}"
        )

        print()

        # =================================
        # Query / Response Matching
        # =================================
        print("Query / Response Matching:")

        if evidence.get("dns_queries", 0) > 0:
            print_field(
                "Matched Responses:",
                f"{evidence.get('matched_responses', 0)}"
            )

            print_field(
                "Response Match Ratio:",
                f"{evidence.get('response_match_ratio', 0.0):.2%}"
            )
        else:
            print_field(
                "Matched Responses:",
                "N/A"
            )

            print_field(
                "Response Match Ratio:",
                "N/A"
            )

        print()

        # =================================
        # DNS Score
        # =================================
        print("Detection Score:")

        print_field(
            "DNS Score:",
            f"{result.get('confidence', 0)}"
        )

        print()

        # =================================
        # Detection Reasons
        # =================================
        reasons = evidence.get("reasons", [])

        if reasons:
            print("Detection Reasons:")

            for reason in reasons:
                print_field(
                    reason,
                    "",
                    prefix="- "
                )


# =================================
# Traffic Rate Anomaly Detection
# =================================
def display_traffic_rates(results):
    print()
    print("-" * MENU_WIDTH)
    print("TRAFFIC RATE ANOMALIES")
    print("-" * MENU_WIDTH)

    if not results:
        print_no_activity()
        return

    for result in results:
        evidence = result["evidence"]

        print_alert_header(
            "Abnormal Traffic Rate Detected",
            result
        )

        print()

        # =================================
        # Traffic Volume
        # =================================
        print("Traffic Volume:")

        print_field("Packets:", f"{evidence['packets']}")

        print_field("Bytes:", f"{evidence['bytes']}")

        print_field(
            "Average Packet Size:",
            f"{evidence['average_packet_size']:.2f} bytes"
        )

        print()

        # =================================
        # Traffic Rates
        # =================================
        print("Traffic Rates:")

        print_field("Packets/sec:", f"{evidence['packets_per_second']:.2f}")

        print_field("Bytes/sec:", f"{evidence['bytes_per_second']:.2f}")

        print()

        # =================================
        # Capture Baseline Analysis
        # =================================
        print("Capture Baseline Analysis:")

        print_field("Baseline Packets:", f"{evidence['baseline_packets']:.2f}")

        print_field("Baseline Bytes:", f"{evidence['baseline_bytes']:.2f}")

        print_field(
            "Packet Deviation:",
            f"{evidence['packet_baseline_deviation']:.2f}x"
        )

        print_field(
            "Byte Deviation:",
            f"{evidence['byte_baseline_deviation']:.2f}x"
        )

        print()

        # =================================
        # Burst Detection
        # =================================
        print("Burst Detection:")

        print_field(
            "Burst Detected:",
            "YES" if evidence["burst_detected"] else "NO"
        )

        print_field(
            "High Burst Detected:",
            "YES" if evidence["high_burst_detected"] else "NO"
        )

        print()

        # =================================
        # Source Concentration
        # =================================
        print("Source Concentration:")

        print_field("Source Count:", f"{evidence['source_count']}")

        print_field("Busiest Source:", f"{evidence['busiest_source']}")

        print_field("Source Packets:", f"{evidence['busiest_source_packets']}")

        print_field(
            "Source Concentration:",
            f"{evidence['source_concentration']:.2%}"
        )

        print()

        # =================================
        # Source Distribution
        # =================================
        if evidence["source_distribution"]:
            print("Source Distribution:")

            for source, count in sorted(
                evidence["source_distribution"].items(),
                key=lambda item: item[1],
                reverse=True,
            ):
                print_field(
                    source,
                    f"{count} packets"
                )

        print()

        # =================================
        # Destination Concentration
        # =================================
        print("Destination Concentration:")

        print_field("Destination Count:", f"{evidence['destination_count']}")

        print_field("Busiest Destination:", f"{evidence['busiest_destination']}")

        print_field(
            "Destination Packets:",
            f"{evidence['busiest_destination_packets']}"
        )

        print_field(
            "Destination Concentration:",
            f"{evidence['destination_concentration']:.2%}"
        )

        print()

        # =================================
        # Destination Distribution
        # =================================
        if evidence["destination_distribution"]:
            print("Destination Distribution:")

            for destination, count in sorted(
                evidence["destination_distribution"].items(),
                key=lambda item: item[1],
                reverse=True,
            ):
                print_field(
                    destination,
                    f"{count} packets"
                )

        print()

        # =================================
        # Protocol Distribution
        # =================================
        print("Protocol Distribution:")

        for protocol, ratio in sorted(
            evidence["protocol_distribution"].items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            print_field(
                protocol,
                f"{ratio:.2%}"
            )

        print()

        # =================================
        # Time Window
        # =================================
        print("Time Window:")

        print_field(
            "Window:",
            f"{evidence['window']} seconds"
        )

        print_field(
            "Duration:",
            f"{evidence['duration']:.2f} seconds"
        )
