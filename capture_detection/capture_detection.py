from packet_capture.capture import capture_packets
from packet_capture.capture_menu import DURATION_OPTIONS
from suspicious_traffic.suspicious_traffic import suspicious_traffic
from utils.menu_display import MENU_WIDTH, print_two_columns


# =================================
# Capture + Detection Duration
# =================================
def capture_detection_duration_menu():
    print("Select capture duration:")
    print()

    duration_labels = {number: label for number, (label, _) in DURATION_OPTIONS.items()}

    print_two_columns(
        list(DURATION_OPTIONS.keys()),
        duration_labels,
    )

    print()

    while True:
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
# Capture + Detection
# =================================
def capture_and_detect():
    print()
    print("=" * MENU_WIDTH)
    print("Capture + Detection".center(MENU_WIDTH))
    print("=" * MENU_WIDTH)
    print()

    print("Capture will monitor ALL traffic.")
    print()

    duration = capture_detection_duration_menu()

    # =================================
    # Live Capture
    # =================================
    packets, filepath = capture_packets(
        "all",
        duration,
        wait_for_input=False,
    )

    # =================================
    # Validate Capture
    # =================================
    if not packets:
        print("[!] No packets were captured.")
        print()

        input("Press ENTER to return to the Main Menu...")
        return

    print(f"[*] Captured packets: {len(packets)}")

    if filepath:
        print(f"[*] PCAP saved to {filepath}")

    # =================================
    # Detection
    # =================================
    print("[*] Running suspicious traffic detection...")
    print()

    suspicious_traffic(filepath, wait_for_input=False)

    # =================================
    # Completion
    # =================================
    print()
    print("[*] Capture + Detection completed.")
    print()
    input("Press ENTER to return to the Main Menu...")
    print()
