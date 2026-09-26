from detection.arp_anomaly import detect_arp_anomalies
from detection.dns_anomaly import detect_dns_anomalies
from detection.icmp_flood import detect_icmp_floods
from detection.port_scan import detect_port_scans
from detection.syn_flood import detect_syn_floods
from detection.traffic_rate import detect_traffic_rate_anomalies
from detection.unusual_port import detect_unusual_ports


# =================================
# Detection Engine
# =================================
def detect(packets):
    return {
        "port_scan": detect_port_scans(packets),
        "unusual_port": detect_unusual_ports(packets),
        "syn_flood": detect_syn_floods(packets),
        "icmp_flood": detect_icmp_floods(packets),
        "arp_anomaly": detect_arp_anomalies(packets),
        "dns_anomaly": detect_dns_anomalies(packets),
        "traffic_rate": detect_traffic_rate_anomalies(packets),
    }
