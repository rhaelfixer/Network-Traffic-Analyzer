from collections import Counter, defaultdict
from math import log2

from scapy.all import DNS, IP, UDP, IPv6, Raw, defragment

from config.config import CONFIG


# =================================
# Shannon Entropy
# =================================
def calculate_entropy(values):
    if not values:
        return 0.0

    counts = Counter(values)
    total = len(values)

    entropy = 0.0

    for count in counts.values():
        probability = count / total

        if probability > 0:
            entropy -= probability * log2(probability)

    return entropy


# =================================
# Character Entropy
# =================================
def calculate_character_entropy(domain):
    if not domain:
        return 0.0

    characters = [character.lower() for character in domain if character.isalnum()]

    if not characters:
        return 0.0

    return calculate_entropy(characters)


# =================================
# Label Entropy
# =================================
def calculate_label_entropy(domain):
    if not domain:
        return 0.0

    labels = domain.split(".")
    label_entropies = []

    for label in labels:
        if not label:
            continue

        entropy = calculate_character_entropy(label)

        if entropy > 0:
            label_entropies.append(entropy)

    if not label_entropies:
        return 0.0

    return sum(label_entropies) / len(label_entropies)


# =================================
# Domain Length Statistics
# =================================
def calculate_domain_length_statistics(domains):
    if not domains:
        return {
            "average_domain_length": 0.0,
            "maximum_domain_length": 0,
            "average_label_length": 0.0,
            "maximum_label_length": 0,
        }

    domain_lengths = []
    label_lengths = []

    for domain in domains:
        domain_lengths.append(len(domain))

        labels = [label for label in domain.split(".") if label]

        for label in labels:
            label_lengths.append(len(label))

    return {
        "average_domain_length": (sum(domain_lengths) / len(domain_lengths)),
        "maximum_domain_length": max(domain_lengths),
        "average_label_length": (
            sum(label_lengths) / len(label_lengths) if label_lengths else 0.0
        ),
        "maximum_label_length": (max(label_lengths) if label_lengths else 0),
    }


# =================================
# Digit Ratio
# =================================
def calculate_digit_ratio(domains):
    characters = []

    for domain in domains:
        characters.extend(
            character.lower() for character in domain if character.isalnum()
        )

    if not characters:
        return 0.0

    digit_count = sum(character.isdigit() for character in characters)

    return digit_count / len(characters)


# =================================
# Domain Entropy Statistics
# =================================
def calculate_domain_entropy_statistics(domains):
    if not domains:
        return {
            "average_character_entropy": 0.0,
            "maximum_character_entropy": 0.0,
            "average_label_entropy": 0.0,
            "maximum_label_entropy": 0.0,
            "domain_frequency_entropy": 0.0,
        }

    character_entropies = []
    label_entropies = []

    for domain in domains:
        character_entropies.append(calculate_character_entropy(domain))

        label_entropies.append(calculate_label_entropy(domain))

    return {
        "average_character_entropy": (
            sum(character_entropies) / len(character_entropies)
        ),
        "maximum_character_entropy": max(character_entropies),
        "average_label_entropy": (sum(label_entropies) / len(label_entropies)),
        "maximum_label_entropy": max(label_entropies),
        "domain_frequency_entropy": (calculate_entropy(domains)),
    }


# =================================
# Extract Domain
# =================================
def extract_domain(dns):
    if not dns.qd:
        return None

    try:
        domain = dns.qd.qname
    except (
        AttributeError,
        IndexError,
        TypeError,
    ):
        return None

    if isinstance(domain, bytes):
        domain = domain.decode(
            "utf-8",
            errors="ignore",
        )

    if not isinstance(domain, str):
        return None

    domain = domain.rstrip(".")

    if not domain:
        return None

    return domain


# =================================
# Get IP Addresses
# =================================
def get_ip_addresses(packet):
    if packet.haslayer(IP):
        return (
            packet[IP].src,
            packet[IP].dst,
        )

    if packet.haslayer(IPv6):
        return (
            packet[IPv6].src,
            packet[IPv6].dst,
        )

    return None, None


# =================================
# Parse DNS Payload
# =================================
def parse_dns_payload(payload):
    if not payload:
        return None

    try:
        dns = DNS(payload)

    except (
        ValueError,
        IndexError,
        TypeError,
    ):
        return None

    try:
        if dns.id is None:
            return None

        if dns.qr not in (0, 1):
            return None

    except (
        AttributeError,
        TypeError,
        ValueError,
    ):
        return None

    return dns


# =================================
# Reassemble IP Fragments
# =================================
def reassemble_ip_fragments(packets):
    fragmented_packets = []
    normal_packets = []

    for packet in packets:
        if packet.haslayer(IP):
            ip = packet[IP]

            if ip.flags.MF or ip.frag != 0:
                fragmented_packets.append(packet)
            else:
                normal_packets.append(packet)

        else:
            normal_packets.append(packet)

    if not fragmented_packets:
        return normal_packets

    try:
        reassembled = defragment(fragmented_packets)

    except (
        ValueError,
        IndexError,
        TypeError,
    ):
        return packets

    return normal_packets + list(reassembled)


# =================================
# Extract DNS Packet
# =================================
def extract_dns_packet(packet):
    # ---------------------------------
    # Existing DNS layer
    # ---------------------------------
    if packet.haslayer(DNS):
        return packet[DNS]

    # ---------------------------------
    # Must contain UDP
    # ---------------------------------
    if not packet.haslayer(UDP):
        return None

    # ---------------------------------
    # Must contain Raw payload
    # ---------------------------------
    if not packet.haslayer(Raw):
        return None

    payload = packet[Raw].load

    return parse_dns_payload(payload)


# =================================
# Create DNS Window
# =================================
def create_dns_window():
    return {
        # ---------------------------------
        # DNS Traffic
        # ---------------------------------
        "queries": 0,
        "responses": 0,
        # ---------------------------------
        # Query Information
        # ---------------------------------
        "query_domains": [],
        "query_types": Counter(),
        "query_sources": Counter(),
        "query_destinations": Counter(),
        # ---------------------------------
        # Response Information
        # ---------------------------------
        "response_domains": [],
        "response_sources": Counter(),
        "response_destinations": Counter(),
        "nxdomain": 0,
        # ---------------------------------
        # Query / Response Matching
        # ---------------------------------
        "query_ids": set(),
        "response_ids": set(),
        # ---------------------------------
        # Timing
        # ---------------------------------
        "first_seen": None,
        "last_seen": None,
    }


# =================================
# Safe Config Getter
# =================================
def config_value(config, name, default):
    return getattr(
        config,
        name,
        default,
    )


# =================================
# DNS Anomaly Detection
# =================================
def detect_dns_anomalies(packets):
    config = CONFIG.dns_anomaly
    dns_query_types = CONFIG.dns_query_types

    # =================================
    # Configuration
    # =================================
    window_size = config_value(
        config,
        "window",
        60,
    )

    min_dns_rate = config_value(
        config,
        "min_dns_rate",
        1000.0,
    )

    min_dns_packets = config_value(
        config,
        "min_dns_packets",
        100,
    )

    min_query_rate = config_value(
        config,
        "min_query_rate",
        100.0,
    )

    min_query_count = config_value(
        config,
        "min_query_count",
        100,
    )

    min_unique_domain_ratio = config_value(
        config,
        "min_unique_domain_ratio",
        0.30,
    )

    min_nxdomain_ratio = config_value(
        config,
        "min_nxdomain_ratio",
        0.20,
    )

    min_domain_character_entropy = config_value(
        config,
        "min_domain_character_entropy",
        3.50,
    )

    min_domain_label_entropy = config_value(
        config,
        "min_domain_label_entropy",
        2.00,
    )

    max_normal_label_length = config_value(
        config,
        "max_normal_label_length",
        30,
    )

    min_digit_ratio = config_value(
        config,
        "min_digit_ratio",
        0.20,
    )

    min_confidence = config_value(
        config,
        "min_confidence",
        60,
    )

    # =================================
    # Reassemble IP Fragments
    # =================================
    packets = reassemble_ip_fragments(packets)

    # =================================
    # DNS Windows
    # =================================
    traffic = defaultdict(create_dns_window)

    capture_start = None

    # =================================
    # Collect DNS Traffic
    # =================================
    for packet in packets:
        dns = extract_dns_packet(packet)

        if dns is None:
            continue

        source, destination = get_ip_addresses(packet)

        if source is None or destination is None:
            continue

        timestamp = float(packet.time)

        # ---------------------------------
        # Capture Start
        # ---------------------------------
        if capture_start is None:
            capture_start = timestamp

        # ---------------------------------
        # Time Window
        # ---------------------------------
        window = int((timestamp - capture_start) // window_size)

        entry = traffic[window]

        # ---------------------------------
        # Timestamp
        # ---------------------------------
        if entry["first_seen"] is None:
            entry["first_seen"] = timestamp

        entry["last_seen"] = timestamp

        # =================================
        # DNS QUERY
        # =================================
        if dns.qr == 0:
            entry["queries"] += 1

            # ---------------------------------
            # Query Source
            # ---------------------------------
            entry["query_sources"][source] += 1

            # ---------------------------------
            # Query Destination
            # ---------------------------------
            entry["query_destinations"][destination] += 1

            # ---------------------------------
            # Transaction ID
            # ---------------------------------
            try:
                entry["query_ids"].add(int(dns.id))
            except (
                AttributeError,
                TypeError,
                ValueError,
            ):
                pass

            # ---------------------------------
            # Domain
            # ---------------------------------
            domain = extract_domain(dns)

            if domain:
                entry["query_domains"].append(domain)

            # ---------------------------------
            # Query Type
            # ---------------------------------
            try:
                query_type = int(dns.qd.qtype)
            except (
                AttributeError,
                IndexError,
                TypeError,
                ValueError,
            ):
                query_type = 0

            if query_type:
                entry["query_types"][query_type] += 1

        # =================================
        # DNS RESPONSE
        # =================================
        elif dns.qr == 1:
            entry["responses"] += 1

            # ---------------------------------
            # Response Source
            # ---------------------------------
            entry["response_sources"][source] += 1

            # ---------------------------------
            # Response Destination
            # ---------------------------------
            entry["response_destinations"][destination] += 1

            # ---------------------------------
            # Transaction ID
            # ---------------------------------
            try:
                entry["response_ids"].add(int(dns.id))
            except (
                AttributeError,
                TypeError,
                ValueError,
            ):
                pass

            # ---------------------------------
            # Response Code
            # ---------------------------------
            try:
                response_code = int(dns.rcode)
            except (
                AttributeError,
                TypeError,
                ValueError,
            ):
                response_code = 0

            # ---------------------------------
            # NXDOMAIN
            # ---------------------------------
            if response_code == 3:
                entry["nxdomain"] += 1

            # ---------------------------------
            # Response Domain
            # ---------------------------------
            domain = extract_domain(dns)

            if domain:
                entry["response_domains"].append(domain)

    # =================================
    # Analyze Windows
    # =================================
    results = []

    for data in traffic.values():
        queries = data["queries"]
        responses = data["responses"]

        total_dns_packets = queries + responses

        if total_dns_packets == 0:
            continue

        # =================================
        # Duration
        # =================================
        duration = max(
            data["last_seen"] - data["first_seen"],
            0.001,
        )

        # =================================
        # DNS Rates
        # =================================
        dns_rate = total_dns_packets / duration

        query_rate = queries / duration if queries > 0 else 0.0

        response_rate = responses / duration if responses > 0 else 0.0

        # =================================
        # Select Domain Dataset
        # =================================
        #
        # If queries exist:
        #     analyze query domains.
        #
        # If there are no queries:
        #     analyze response domains.
        #
        if queries > 0:
            analysis_domains = data["query_domains"]
            domain_basis = "queries"

        else:
            analysis_domains = data["response_domains"]
            domain_basis = "responses"

        # =================================
        # Domain Statistics
        # =================================
        unique_domains = len(set(analysis_domains))

        domain_denominator = queries if queries > 0 else responses

        unique_domain_ratio = (
            unique_domains / domain_denominator if domain_denominator > 0 else 0.0
        )

        # =================================
        # Response Domain Statistics
        # =================================
        response_domains = data["response_domains"]

        unique_response_domains = len(set(response_domains))

        response_unique_domain_ratio = (
            unique_response_domains / responses if responses > 0 else 0.0
        )

        # =================================
        # NXDOMAIN Ratio
        # =================================
        nxdomain_ratio = data["nxdomain"] / responses if responses > 0 else 0.0

        # =================================
        # Query Types
        # =================================
        query_type_count = len(data["query_types"])

        query_types = {
            dns_query_types.get(
                query_type,
                f"TYPE{query_type}",
            ): count
            for query_type, count in data["query_types"].items()
        }

        # =================================
        # Domain Statistics
        # =================================
        length_stats = calculate_domain_length_statistics(analysis_domains)

        average_domain_length = length_stats["average_domain_length"]

        maximum_domain_length = length_stats["maximum_domain_length"]

        average_label_length = length_stats["average_label_length"]

        maximum_label_length = length_stats["maximum_label_length"]

        # =================================
        # Digit Ratio
        # =================================
        digit_ratio = calculate_digit_ratio(analysis_domains)

        # =================================
        # Domain Entropy
        # =================================
        entropy_stats = calculate_domain_entropy_statistics(analysis_domains)

        domain_frequency_entropy = entropy_stats["domain_frequency_entropy"]

        average_character_entropy = entropy_stats["average_character_entropy"]

        maximum_character_entropy = entropy_stats["maximum_character_entropy"]

        average_label_entropy = entropy_stats["average_label_entropy"]

        maximum_label_entropy = entropy_stats["maximum_label_entropy"]

        # =================================
        # Response Entropy
        # =================================
        response_entropy_stats = calculate_domain_entropy_statistics(response_domains)

        response_character_entropy = response_entropy_stats["average_character_entropy"]

        response_label_entropy = response_entropy_stats["average_label_entropy"]

        # =================================
        # Source Concentration
        # =================================
        query_sources = data["query_sources"]

        response_sources = data["response_sources"]

        if queries > 0 and query_sources:
            source_count = len(query_sources)

            (
                busiest_source,
                busiest_source_packets,
            ) = query_sources.most_common(1)[0]

            source_concentration = busiest_source_packets / queries

            source_packet_basis = "queries"

        elif responses > 0 and response_sources:
            source_count = len(response_sources)

            (
                busiest_source,
                busiest_source_packets,
            ) = response_sources.most_common(1)[0]

            source_concentration = busiest_source_packets / responses

            source_packet_basis = "responses"

        else:
            source_count = 0
            busiest_source = None
            busiest_source_packets = 0
            source_concentration = 0.0
            source_packet_basis = "none"

        # =================================
        # DNS Server Concentration
        # =================================
        query_destinations = data["query_destinations"]

        response_destinations = data["response_destinations"]

        if queries > 0 and query_destinations:
            destination_count = len(query_destinations)

            (
                busiest_destination,
                busiest_destination_packets,
            ) = query_destinations.most_common(1)[0]

            destination_concentration = busiest_destination_packets / queries

            destination_packet_basis = "queries"

        elif responses > 0 and response_destinations:
            destination_count = len(response_destinations)

            (
                busiest_destination,
                busiest_destination_packets,
            ) = response_destinations.most_common(1)[0]

            destination_concentration = busiest_destination_packets / responses

            destination_packet_basis = "responses"

        else:
            destination_count = 0
            busiest_destination = None
            busiest_destination_packets = 0
            destination_concentration = 0.0
            destination_packet_basis = "none"

        # =================================
        # Query / Response Matching
        # =================================
        matched_responses = len(data["query_ids"] & data["response_ids"])

        response_match_ratio = matched_responses / queries if queries > 0 else 0.0

        # =================================
        # Confidence Score
        # =================================
        score = 0
        reasons = []

        # =================================
        # DNS Traffic Rate
        # =================================
        if dns_rate >= min_dns_rate:
            score += 20
            reasons.append("Extremely high DNS traffic rate")

        # =================================
        # DNS Traffic Volume
        # =================================
        if total_dns_packets >= min_dns_packets:
            score += 15
            reasons.append("High DNS traffic volume")

        # =================================
        # Query-Based Detection
        # =================================
        if queries > 0:
            # ---------------------------------
            # Query Rate
            # ---------------------------------
            if query_rate >= min_query_rate:
                score += 20
                reasons.append("High DNS query rate")

            # ---------------------------------
            # Query Count
            # ---------------------------------
            if queries >= min_query_count:
                score += 10
                reasons.append("High DNS query volume")

            # ---------------------------------
            # Unique Domains
            # ---------------------------------
            if unique_domain_ratio >= min_unique_domain_ratio:
                score += 15
                reasons.append("High unique-domain ratio")

            # ---------------------------------
            # NXDOMAIN
            # ---------------------------------
            if nxdomain_ratio >= min_nxdomain_ratio:
                score += 20
                reasons.append("High NXDOMAIN ratio")

            # ---------------------------------
            # Character Entropy
            # ---------------------------------
            if average_character_entropy >= min_domain_character_entropy:
                score += 10
                reasons.append("High average domain character entropy")

            # ---------------------------------
            # Maximum Character Entropy
            # ---------------------------------
            if maximum_character_entropy >= (min_domain_character_entropy + 0.5):
                score += 5
                reasons.append("Extremely high domain character entropy")

            # ---------------------------------
            # Label Entropy
            # ---------------------------------
            if average_label_entropy >= min_domain_label_entropy:
                score += 10
                reasons.append("High DNS label entropy")

            # ---------------------------------
            # Long Label
            # ---------------------------------
            if maximum_label_length >= max_normal_label_length:
                score += 5
                reasons.append("Unusually long DNS label")

            # ---------------------------------
            # Digit Ratio
            # ---------------------------------
            if digit_ratio >= min_digit_ratio:
                score += 5
                reasons.append("High digit ratio in DNS domains")

            # ---------------------------------
            # Query Type Diversity
            # ---------------------------------
            if query_type_count >= 3:
                score += 5
                reasons.append("Multiple DNS query types")

            # ---------------------------------
            # Source Concentration
            # ---------------------------------
            if source_concentration >= 0.95:
                score += 10
                reasons.append("DNS queries highly concentrated on one source")

            elif source_concentration >= 0.90:
                score += 5
                reasons.append("DNS queries concentrated on one source")

            # ---------------------------------
            # DNS Server Concentration
            # ---------------------------------
            if destination_concentration >= 0.95:
                score += 10
                reasons.append("DNS queries highly concentrated on one DNS server")

            elif destination_concentration >= 0.90:
                score += 5
                reasons.append("DNS queries concentrated on one DNS server")

            # ---------------------------------
            # Query / Response Matching
            # ---------------------------------
            if queries >= min_query_count and response_match_ratio < 0.50:
                score += 10
                reasons.append("Low DNS query/response matching ratio")

        # =================================
        # Response-Only Detection
        # =================================
        else:
            reasons.append("No DNS queries captured, response-side analysis used")

            # ---------------------------------
            # Response Source Concentration
            # ---------------------------------
            if source_concentration >= 0.95:
                score += 10
                reasons.append("DNS responses highly concentrated on one source")

            elif source_concentration >= 0.90:
                score += 5
                reasons.append("DNS responses concentrated on one source")

            # ---------------------------------
            # Response Destination Concentration
            # ---------------------------------
            if destination_concentration >= 0.95:
                score += 10
                reasons.append("DNS responses highly concentrated on one destination")

            elif destination_concentration >= 0.90:
                score += 5
                reasons.append("DNS responses concentrated on one destination")

            # ---------------------------------
            # Response Domain Diversity
            # ---------------------------------
            if unique_response_domains > 0 and response_unique_domain_ratio >= 0.10:
                score += 5
                reasons.append("Multiple unique DNS response domains")

            # ---------------------------------
            # Response NXDOMAIN
            # ---------------------------------
            if nxdomain_ratio >= min_nxdomain_ratio:
                score += 20
                reasons.append("High NXDOMAIN response ratio")

            # ---------------------------------
            # Response Character Entropy
            # ---------------------------------
            if response_character_entropy >= min_domain_character_entropy:
                score += 10
                reasons.append("High response-domain character entropy")

            # ---------------------------------
            # Response Label Entropy
            # ---------------------------------
            if response_label_entropy >= min_domain_label_entropy:
                score += 10
                reasons.append("High response-domain label entropy")

        # =================================
        # Score Cap
        # =================================
        score = min(
            100,
            score,
        )

        # =================================
        # Minimum Confidence
        # =================================
        if score < min_confidence:
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
                "detector": ("DNS Anomaly Detection"),
                "severity": severity,
                "confidence": round(score),
                "source": busiest_source,
                "destination": (busiest_destination),
                "evidence": {
                    # ---------------------------------
                    # DNS Traffic
                    # ---------------------------------
                    "dns_packets": (total_dns_packets),
                    "dns_queries": queries,
                    "dns_responses": responses,
                    "dns_rate": dns_rate,
                    "query_rate": query_rate,
                    "response_rate": response_rate,
                    # ---------------------------------
                    # Time
                    # ---------------------------------
                    "duration": duration,
                    "window": window_size,
                    # ---------------------------------
                    # Domain Statistics
                    # ---------------------------------
                    "unique_domains": (unique_domains),
                    "unique_domain_ratio": (unique_domain_ratio),
                    "domain_basis": (domain_basis),
                    "unique_response_domains": (unique_response_domains),
                    "response_unique_domain_ratio": (response_unique_domain_ratio),
                    "average_domain_length": (average_domain_length),
                    "maximum_domain_length": (maximum_domain_length),
                    "average_label_length": (average_label_length),
                    "maximum_label_length": (maximum_label_length),
                    "digit_ratio": digit_ratio,
                    # ---------------------------------
                    # NXDOMAIN
                    # ---------------------------------
                    "nxdomain": (data["nxdomain"]),
                    "nxdomain_ratio": (nxdomain_ratio),
                    # ---------------------------------
                    # Query Types
                    # ---------------------------------
                    "query_types": query_types,
                    "query_type_count": (query_type_count),
                    # ---------------------------------
                    # Entropy
                    # ---------------------------------
                    "domain_frequency_entropy": (domain_frequency_entropy),
                    "average_character_entropy": (average_character_entropy),
                    "maximum_character_entropy": (maximum_character_entropy),
                    "average_label_entropy": (average_label_entropy),
                    "maximum_label_entropy": (maximum_label_entropy),
                    "response_character_entropy": (response_character_entropy),
                    "response_label_entropy": (response_label_entropy),
                    # ---------------------------------
                    # Source Concentration
                    # ---------------------------------
                    "source_count": source_count,
                    "busiest_source": (busiest_source),
                    # IMPORTANT:
                    # Keep both names so either
                    # detector/display code works.
                    "source_packets": (busiest_source_packets),
                    "busiest_source_packets": (busiest_source_packets),
                    "source_concentration": (source_concentration),
                    "source_packet_basis": (source_packet_basis),
                    # ---------------------------------
                    # DNS Server Concentration
                    # ---------------------------------
                    "destination_count": (destination_count),
                    "busiest_destination": (busiest_destination),
                    # IMPORTANT:
                    # Keep both names so either
                    # detector/display code works.
                    "destination_packets": (busiest_destination_packets),
                    "busiest_destination_packets": (busiest_destination_packets),
                    "destination_concentration": (destination_concentration),
                    "destination_packet_basis": (destination_packet_basis),
                    # ---------------------------------
                    # Query / Response Matching
                    # ---------------------------------
                    "matched_responses": (matched_responses),
                    "response_match_ratio": (response_match_ratio),
                    # ---------------------------------
                    # Detection Score
                    # ---------------------------------
                    "score": score,
                    # ---------------------------------
                    # Detection Reasons
                    # ---------------------------------
                    "reasons": reasons,
                },
            }
        )

    return results
