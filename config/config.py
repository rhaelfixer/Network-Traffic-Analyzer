from dataclasses import dataclass
from pathlib import Path

import yaml


# =================================
# Configuration Models
# =================================
@dataclass(frozen=True)
class PortScanConfig:
    window: int
    min_unique_ports: int
    min_rate: float

    max_response_ratio: float
    min_failure_ratio: float

    min_sequential_ratio: float
    min_target_concentration: float

    min_confidence: int


@dataclass(frozen=True)
class UnusualPortConfig:
    privileged_port_max: int

    dynamic_port_min: int
    dynamic_port_max: int

    min_packets: int

    rare_port_max_frequency: float
    very_rare_port_max_frequency: float

    protocol_mismatch_score: int
    unknown_protocol_score: int

    min_confidence: int


@dataclass(frozen=True)
class SynFloodConfig:
    window: int

    min_packets: int
    min_rate: float

    max_syn_ack_ratio: float
    max_completion_ratio: float
    min_half_open_ratio: float

    min_source_diversity: int

    min_confidence: int


@dataclass(frozen=True)
class IcmpFloodConfig:
    window: int

    min_packets: int
    min_rate: float

    min_request_reply_ratio: float

    min_source_diversity: int
    min_target_concentration: float
    min_burst_score: float

    min_confidence: int


@dataclass(frozen=True)
class ArpAnomalyConfig:
    min_mapping_conflicts: int
    min_ips_per_mac: int

    min_gratuitous_packets: int

    request_reply_imbalance: float

    broadcast_window: int
    min_broadcast_rate: float

    min_confidence: int


@dataclass(frozen=True)
class DnsAnomalyConfig:
    window: int

    min_dns_rate: float
    min_dns_packets: int

    min_query_rate: float
    min_query_count: int

    min_unique_domain_ratio: float
    min_nxdomain_ratio: float

    min_domain_character_entropy: float
    min_domain_label_entropy: float

    max_normal_label_length: int
    min_digit_ratio: float

    min_confidence: int


@dataclass(frozen=True)
class TrafficRateConfig:
    window: int

    min_packets: int
    min_packets_per_second: float

    burst_multiplier: float
    high_burst_multiplier: float

    min_confidence: int


@dataclass(frozen=True)
class Config:
    port_scan: PortScanConfig
    unusual_port: UnusualPortConfig
    syn_flood: SynFloodConfig
    icmp_flood: IcmpFloodConfig
    arp_anomaly: ArpAnomalyConfig
    dns_anomaly: DnsAnomalyConfig
    traffic_rate: TrafficRateConfig

    known_service_ports: dict[int, str]
    high_risk_ports: frozenset[int]
    expected_protocols: dict[int, frozenset[str]]
    dns_query_types: dict[int, str]


# =================================
# Configuration Loader
# =================================
def load_config() -> Config:
    config_path = Path(__file__).with_name("config.yaml")

    with config_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    return Config(
        port_scan=PortScanConfig(**data["port_scan"]),
        unusual_port=UnusualPortConfig(**data["unusual_port"]),
        syn_flood=SynFloodConfig(**data["syn_flood"]),
        icmp_flood=IcmpFloodConfig(**data["icmp_flood"]),
        arp_anomaly=ArpAnomalyConfig(**data["arp_anomaly"]),
        dns_anomaly=DnsAnomalyConfig(**data["dns_anomaly"]),
        traffic_rate=TrafficRateConfig(**data["traffic_rate"]),
        known_service_ports={
            int(port): service for port, service in data["known_service_ports"].items()
        },
        high_risk_ports=frozenset(int(port) for port in data["high_risk_ports"]),
        expected_protocols={
            int(port): frozenset(protocols)
            for port, protocols in data["expected_protocols"].items()
        },
        dns_query_types={
            int(query_type): query_name
            for query_type, query_name in data["dns_query_types"].items()
        },
    )


# =================================
# Global Configuration
# =================================
CONFIG = load_config()
