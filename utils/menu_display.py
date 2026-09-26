# =================================
# Menu Layout Configuration
# =================================
COLUMN_GAP = 15
MENU_WIDTH = 75
EXTENDED_WIDTH = MENU_WIDTH + 25


# =================================
# Menu Layout Functions
# =================================
def print_main_menu(options, labels):
    lines = [f"{number}. {labels[number]}" for number in options]

    block_width = max(map(len, lines))
    padding = max((MENU_WIDTH - block_width) // 2, 0)

    for line in lines:
        print(" " * padding + line)

def print_two_columns(options, labels):
    midpoint = (len(options) + 1) // 2

    left = options[:midpoint]
    right = options[midpoint:]

    left_texts = [f"{number}. {labels[number]}" for number in left]

    right_texts = [f"{number}. {labels[number]}" for number in right]

    column_width = max(map(len, left_texts)) + COLUMN_GAP

    lines = []

    for i, left_text in enumerate(left_texts):
        if i < len(right_texts):
            line = f"{left_text:<{column_width}}{right_texts[i]}"
        else:
            line = left_text

        lines.append(line)

    max_width = max(map(len, lines))
    padding = max((MENU_WIDTH - max_width) // 2, 0)

    for line in lines:
        print(" " * padding + line)
