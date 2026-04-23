from colorama import Fore, Style, init
init()  # starts colourised terminal output on Windows

COLOURS = {
    'CRITICAL': Fore.RED,
    'HIGH': Fore.RED,
    'MEDIUM': Fore.YELLOW,
    'LOW': Fore.CYAN,
}

def print_report(all_findings):
    print("\n========== AWS SECURITY SCAN REPORT ==========")
    print(f"Total issues found: {len(all_findings)}\n")

    for f in all_findings:
        colour = COLOURS.get(f['severity'], Fore.WHITE)
        print(f"{colour}[{f['severity']}]{Style.RESET_ALL} {f['resource']}")
        print(f"  Issue : {f['issue']}")
        print(f"  Fix   : {f['fix']}")
        print()  # blank line between each finding

    if not all_findings:
        print(Fore.GREEN + "No issues found! Your account looks clean." + Style.RESET_ALL)
