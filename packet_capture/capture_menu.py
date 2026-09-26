from packet_capture.bpf_filter import get_custom_bpf_filter
from packet_capture.capture import (
    capture_custom_packets,
    capture_packets,
)
from utils.menu_display import MENU_WIDTH, print_two_columns

# =================================
# Capture Configuration
# =================================
CAPTURE_TYPES = {
    "1": ("All Traffic", "all"),
    # Network
    "2": ("IPv4", "ipv4"),
    "3": ("IPv6", "ipv6"),
    "4": ("ICMP", "icmp"),
    "5": ("ICMPv6", "icmp6"),
    "6": ("ARP", "arp"),
    # Transport
    "7": ("TCP", "tcp"),
    "8": ("UDP", "udp"),
    "9": ("SCTP", "sctp"),
    # Application
    "10": ("DNS", "dns"),
    "11": ("HTTP", "http"),
    "12": ("HTTPS", "https"),
    "13": ("DHCP", "dhcp"),
    "14": ("SSH", "ssh"),
}

NETWORK = [
    "2",
    "3",
    "4",
    "5",
    "6",
]

TRANSPORT = [
    "7",
    "8",
    "9",
]

APPLICATION = [
    "10",
    "11",
    "12",
    "13",
    "14",
]

ADVANCED_OPTIONS = {
    "15": "Custom BPF Filter",
}


# =================================
# Duration Configuration
# =================================
DURATION_OPTIONS = {
    "1": ("15 seconds", 15),
    "2": ("30 seconds", 30),
    "3": ("1 minute", 60),
    "4": ("5 minutes", 300),
    "5": ("10 minutes", 600),
    "6": ("Unlimited", None),
}


# =================================
# Menu Display
# =================================
def show_capture_menu():
    print("=" * MENU_WIDTH)
    print("Packet Capture".center(MENU_WIDTH))
    print("=" * MENU_WIDTH)
    print()

    print("Select Packet Capture Type:".center(MENU_WIDTH))
    print()

    # All Traffic
    print("1. All Traffic".center(MENU_WIDTH))
    print()

    # Network
    print("--- Network ---".center(MENU_WIDTH))

    network_labels = {number: CAPTURE_TYPES[number][0] for number in NETWORK}

    print_two_columns(
        NETWORK,
        network_labels,
    )

    print()

    # Transport
    print("--- Transport ---".center(MENU_WIDTH))

    transport_labels = {number: CAPTURE_TYPES[number][0] for number in TRANSPORT}

    print_two_columns(
        TRANSPORT,
        transport_labels,
    )

    print()

    # Application
    print("--- Application ---".center(MENU_WIDTH))

    application_labels = {number: CAPTURE_TYPES[number][0] for number in APPLICATION}

    print_two_columns(
        APPLICATION,
        application_labels,
    )

    print()

    # Advanced
    print("--- Advanced ---".center(MENU_WIDTH))

    print_two_columns(
        list(ADVANCED_OPTIONS.keys()),
        ADVANCED_OPTIONS,
    )

    print()

    print("16. Back to Main Menu".center(MENU_WIDTH))
    print()


def show_duration_menu():
    print("=" * MENU_WIDTH)
    print("Capture Duration".center(MENU_WIDTH))
    print("=" * MENU_WIDTH)
    print()

    print("Select capture duration:".center(MENU_WIDTH))
    print()

    duration_labels = {number: label for number, (label, _) in DURATION_OPTIONS.items()}

    print_two_columns(
        list(DURATION_OPTIONS.keys()),
        duration_labels,
    )

    print()


# =================================
# Duration Menu
# =================================
def duration_menu():
    while True:
        show_duration_menu()

        choice = input("Select duration: ")

        if choice in DURATION_OPTIONS:
            duration_name, duration = DURATION_OPTIONS[choice]

            print()
            print(f"{duration_name} selected.")
            print()

            return duration

        print()
        print("Invalid option.")
        print()


# =================================
# Capture Menu
# =================================
def capture_menu():
    while True:
        show_capture_menu()

        choice = input("Select: ")

        # Capture Type
        if choice in CAPTURE_TYPES:
            protocol_name, capture_type = CAPTURE_TYPES[choice]

            print()
            print(f"{protocol_name} selected.")
            print()

            duration = duration_menu()

            capture_packets(
                capture_type,
                duration,
            )

        # Custom BPF Filter
        elif choice == "15":
            print()
            print("Custom BPF Filter selected.")
            print()

            custom_filter = get_custom_bpf_filter()

            print()
            print(f"[*] Custom BPF Filter: {custom_filter}")
            print()

            duration = duration_menu()

            capture_custom_packets(
                custom_filter,
                duration,
            )

        # Back
        elif choice == "16":
            return

        # Invalid
        else:
            print()
            print("Invalid option.")
            print()
