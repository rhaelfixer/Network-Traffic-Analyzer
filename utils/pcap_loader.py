import os

from scapy.all import rdpcap

from utils.menu_display import MENU_WIDTH

# =================================
# Capture Configuration
# =================================
CAPTURE_DIRECTORY = "./captures"


# =================================
# Capture Files
# =================================
def get_capture_files():
    if not os.path.exists(CAPTURE_DIRECTORY):
        return []

    files = []

    for filename in os.listdir(CAPTURE_DIRECTORY):
        if filename.lower().endswith(".pcap"):
            files.append(filename)

    files.sort(reverse=True)

    return files


# =================================
# Capture File Selection
# =================================
def select_capture_file():
    files = get_capture_files()

    if not files:
        print()
        print("[!] No PCAP files found.")
        print(f"[!] Capture directory: {CAPTURE_DIRECTORY}")
        print()

        input("Press ENTER to return...")
        return None

    while True:
        print()
        print("=" * MENU_WIDTH)
        print("Capture Files".center(MENU_WIDTH))
        print("=" * MENU_WIDTH)
        print()

        print("Select a capture file:".center(MENU_WIDTH))
        print()

        lines = []

        for index, filename in enumerate(files, start=1):
            lines.append(f"{index}. {filename}")

        lines.append(f"{len(files) + 1}. Back")

        block_width = max(len(line) for line in lines)
        padding = (MENU_WIDTH - block_width) // 2

        for line in lines:
            print(f"{' ' * padding}{line}")

        print()

        choice = input("Select: ").strip()

        print()

        try:
            choice = int(choice)

        except ValueError:
            print()
            print("Invalid option.")
            print()
            continue

        # Back
        if choice == len(files) + 1:
            return None

        # Valid PCAP
        if 1 <= choice <= len(files):
            return os.path.join(
                CAPTURE_DIRECTORY,
                files[choice - 1],
            )

        print()
        print("Invalid option.")
        print()


# =================================
# Load PCAP
# =================================
def load_capture(filepath):
    print(f"[*] Loading capture: {filepath}")

    try:
        packets = rdpcap(filepath)

    except OSError as error:
        print()
        print("[!] Failed to load capture.")
        print(f"[!] Error: {error}")
        print()

        input("Press ENTER to return...")
        return None

    print(f"[*] Loaded {len(packets)} packets.")

    return packets
