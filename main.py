from capture_detection.capture_detection import capture_and_detect
from packet_capture.capture_menu import capture_menu
from suspicious_traffic.suspicious_traffic import suspicious_traffic
from traffic_summary.summary_menu import summary_menu
from utils.menu_display import MENU_WIDTH, print_main_menu

# =================================
# Main Menu Configuration
# =================================
MENU_OPTIONS = {
    "1": "Packet Capture",
    "2": "Traffic Summary",
    "3": "Detect Suspicious Traffic",
    "4": "Capture + Detection",
    "5": "Exit",
}


# =================================
# Main Menu Display
# =================================
def show_menu():
    print("=" * MENU_WIDTH)
    print("Network Traffic Analyzer".center(MENU_WIDTH))
    print("=" * MENU_WIDTH)
    print()

    print("Select an option:".center(MENU_WIDTH))
    print()

    print_main_menu(
        list(MENU_OPTIONS.keys()),
        MENU_OPTIONS,
    )

    print()


# =================================
# Main Program
# =================================
def main():
    try:
        while True:
            show_menu()

            choice = input("Select option: ")

            if choice == "1":
                print()
                capture_menu()

            elif choice == "2":
                print()
                summary_menu()

            elif choice == "3":
                suspicious_traffic()

            elif choice == "4":
                capture_and_detect()

            elif choice == "5":
                print("Exiting...")
                break

            else:
                print("Invalid option.")

            print()

    except KeyboardInterrupt:
        print()
        print("[*] Exiting...")


# =================================
# Program Entry Point
# =================================
if __name__ == "__main__":
    main()
