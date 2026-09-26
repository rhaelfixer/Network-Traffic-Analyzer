from traffic_summary.summary import (
    conversation_statistics,
    ip_statistics,
    protocol_statistics,
    tcp_statistics,
    traffic_summary,
)
from utils.menu_display import MENU_WIDTH, print_two_columns

# =================================
# Summary Configuration
# =================================
SUMMARY_OPTIONS = {
    "1": "Traffic Summary",
    "2": "Protocol Statistics",
    "3": "IP Statistics",
    "4": "TCP Statistics",
    "5": "Conversation Statistics",
    "6": "Back to Main Menu",
}


# =================================
# Menu Display
# =================================
def show_summary_menu():
    print("=" * MENU_WIDTH)
    print("Traffic Summary".center(MENU_WIDTH))
    print("=" * MENU_WIDTH)
    print()

    print("Select Traffic Summary Type:".center(MENU_WIDTH))
    print()

    print_two_columns(
        list(SUMMARY_OPTIONS.keys()),
        SUMMARY_OPTIONS,
    )

    print()


# =================================
# Summary Menu
# =================================
def summary_menu():
    while True:
        show_summary_menu()

        choice = input("Select: ")

        # Traffic Summary
        if choice == "1":
            print()
            print("Traffic Summary selected.")
            print()

            traffic_summary()

        # Protocol Statistics
        elif choice == "2":
            print()
            print("Protocol Statistics selected.")
            print()

            protocol_statistics()

        # IP Statistics
        elif choice == "3":
            print()
            print("IP Statistics selected.")
            print()

            ip_statistics()

        # TCP Statistics
        elif choice == "4":
            print()
            print("TCP Statistics selected.")
            print()

            tcp_statistics()

        # Conversation Statistics
        elif choice == "5":
            print()
            print("Conversation Statistics selected.")
            print()

            conversation_statistics()

        # Back
        elif choice == "6":
            return

        # Invalid
        else:
            print()
            print("Invalid option.")
            print()
