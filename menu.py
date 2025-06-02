#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import subprocess
import sys
import os
from rich.console import Console
from rich.panel import Panel
from pyfiglet import Figlet
import getpass
console = Console()

# === Groups with Descriptions ===
groups = {
    "blackarch-webapp": (
        "Web Applications",
        "Tools for testing, auditing, and exploiting web applications and services."
    ),
    "blackarch-fuzzer": (
        "Fuzzing",
        "Automated tools for finding bugs and vulnerabilities by sending malformed input."
    ),
    "blackarch-scanner": (
        "Network Scanners",
        "Network and vulnerability scanners for discovering hosts, services, and weaknesses."
    ),
    "blackarch-proxy": (
        "Proxy Tools",
        "HTTP/HTTPS and other proxy tools for intercepting and modifying traffic."
    ),
    "blackarch-windows": (
        "Windows Tools",
        "Security and exploitation tools specifically for Windows environments."
    ),
    "blackarch-dos": (
        "Denial of Service",
        "Tools for performing and testing Denial of Service (DoS) attacks."
    ),
    "blackarch-disassembler": (
        "Disassemblers",
        "Tools for converting binaries into assembly code for analysis."
    ),
    "blackarch-sniffer": (
        "Sniffing & Spoofing",
        "Network sniffers and spoofers for capturing and manipulating network traffic."
    ),
    "blackarch-voip": (
        "VoIP Tools",
        "Voice over IP analysis and attack tools."
    ),
    "blackarch-fingerprint": (
        "Fingerprinting",
        "Tools for identifying systems, services, and software versions."
    ),
    "blackarch-networking": (
        "Networking",
        "General networking utilities for diagnostics and analysis."
    ),
    "blackarch-recon": (
        "Reconnaissance",
        "Information gathering and reconnaissance tools."
    ),
    "blackarch-cracker": (
        "Password Cracking",
        "Tools for brute-forcing and cracking passwords and hashes."
    ),
    "blackarch-exploitation": (
        "Exploitation",
        "Frameworks and tools for exploiting vulnerabilities."
    ),
    "blackarch-spoof": (
        "Spoofing",
        "Tools for spoofing network identities and traffic."
    ),
    "blackarch-forensic": (
        "Forensics",
        "Digital forensics tools for investigation and analysis."
    ),
    "blackarch-crypto": (
        "Cryptography",
        "Cryptographic tools for encryption, decryption, and analysis."
    ),
    "blackarch-backdoor": (
        "Backdoors",
        "Tools for creating and managing backdoors."
    ),
    "blackarch-defensive": (
        "Defensive Tools",
        "Security tools for defense, monitoring, and protection."
    ),
    "blackarch-wireless": (
        "Wireless Attacks",
        "Tools for attacking and analyzing wireless networks."
    ),
    "blackarch-automation": (
        "Automation",
        "Automation frameworks and scripting tools."
    ),
    "blackarch-radio": (
        "Radio Tools",
        "Software-defined radio and RF analysis tools."
    ),
    "blackarch-binary": (
        "Binary Analysis",
        "Tools for analyzing binary files and executables."
    ),
    "blackarch-packer": (
        "Packers",
        "Tools for packing and obfuscating binaries."
    ),
    "blackarch-reversing": (
        "Reverse Engineering",
        "Reverse engineering tools for software and hardware."
    ),
    "blackarch-mobile": (
        "Mobile Tools",
        "Security tools for mobile devices and applications."
    ),
    "blackarch-malware": (
        "Malware Analysis",
        "Tools for analyzing and dissecting malware."
    ),
    "blackarch-code-audit": (
        "Code Auditing",
        "Source code auditing and static analysis tools."
    ),
    "blackarch-social": (
        "Social Engineering",
        "Tools for social engineering and human-based attacks."
    ),
    "blackarch-honeypot": (
        "Honeypots",
        "Decoy systems for detecting and studying attacks."
    ),
    "blackarch-misc": (
        "Miscellaneous",
        "Various tools that don't fit other categories."
    ),
    "blackarch-wordlist": (
        "Wordlists",
        "Collections of passwords and wordlists for attacks."
    ),
    "blackarch-decompiler": (
        "Decompilers",
        "Tools for converting binaries back to source code."
    ),
    "blackarch-config": (
        "Configuration",
        "Tools for managing and auditing configurations."
    ),
    "blackarch-debugger": (
        "Debuggers",
        "Debugging tools for software and binaries."
    ),
    "blackarch-bluetooth": (
        "Bluetooth Tools",
        "Bluetooth protocol analysis and attack tools."
    ),
    "blackarch-database": (
        "Database Tools",
        "Database assessment and exploitation tools."
    ),
    "blackarch-automobile": (
        "Automobile Hacking",
        "Tools for vehicle and CAN bus security testing."
    ),
    "blackarch-hardware": (
        "Hardware Hacking",
        "Tools for hardware analysis and hacking."
    ),
    "blackarch-nfc": (
        "NFC Tools",
        "Near Field Communication and RFID tools."
    ),
    "blackarch-tunnel": (
        "Tunneling",
        "Tunneling and VPN tools for network traffic."
    ),
    "blackarch-drone": (
        "Drone Hacking",
        "Tools for drone analysis and exploitation."
    ),
    "blackarch-unpacker": (
        "Unpackers",
        "Tools for unpacking and deobfuscating binaries."
    ),
    "blackarch-firmware": (
        "Firmware Analysis",
        "Firmware extraction and analysis tools."
    ),
    "blackarch-keylogger": (
        "Keyloggers",
        "Tools for recording keystrokes."
    ),
    "blackarch-stego": (
        "Steganography",
        "Tools for hiding and extracting data in files."
    ),
    "blackarch-anti-forensic": (
        "Anti-Forensics",
        "Tools for evading forensic analysis."
    ),
    "blackarch-ids": (
        "Intrusion Detection",
        "Intrusion detection and prevention systems."
    ),
    "blackarch-threat-model": (
        "Threat Modeling",
        "Tools for modeling and assessing threats."
    ),
    "blackarch-gpu": (
        "GPU Tools",
        "GPU-accelerated security and cracking tools."
    ),
}

# === all the tool from blackarch slim iso  ===
slim_Edition = [
    "mass", "arp-scan", "aquatone", "binwalk", "bulk-extractor", "bully", "burpsuite", "cewl", "chaos-client", "chntpw", "commix", "crackmapexec", "creddump",
    "crunch", "davtest", "dbd", "dirb", "dirbuster", "dmitry", "dns2tcp", "dnschef", "dnsenum", "dnsrecon", "dnsx", "enum4linux", "exiv2", "exploitdb",
    "faradaysec", "fern-wifi-cracker", "ffuf", "fierce", "findomain", "fping", "gobuster", "guymager", "hashcat", "hashcat-utils", "hashdeep", "hashid",
    "hash-identifier", "hping", "hotpatch", "httpx", "hydra", "ike-scan", "inetsim", "iodine", "john", "kismet", "laudanum", "lbd", "legion", "lulzbuster",
    "macchanger", "magicrescue", "maltego", "maskprocessor", "massdns", "masscan", "metasploit", "msfdb", "mimikatz", "mitmproxy", "multimac", "nbtscan",
    "ncrack", "netdiscover", "netmask", "netsed", "netsniff-ng", "ngrep", "nikto", "nmap", "nuclei", "nuclei-templates", "onesixtyone", "openbsd-netcat",
    "ophcrack", "patator", "pdfid", "pdf-parser", "pipal", "pixiewps", "powersploit", "proxychains-ng", "proxytunnel", "proxify", "pth-toolkit", "ptunnel",
    "pwnat", "radare2", "reaver", "rebind", "recon-ng", "redsocks", "responder", "rsmangler", "sakis3g", "samdump2", "sbd", "scalpel", "scrounge-ntfs",
    "seclists", "set", "skipfish", "sleuthkit", "smbmap", "snmpcheck", "socat", "sploitctl", "spiderfoot", "spooftooph", "sqlmap", "ssldump", "sslscan",
    "sslsplit", "sslyze", "statsprocessor", "stunnel", "subfinder", "swaks", "tcpdump", "tcpick", "tcpreplay", "thc-ipv6", "thc-pptp-bruter", "torctl",
    "theharvester", "udptunnel", "unix-privesc-check", "voiphopper", "wafw00f", "wce", "webshells", "weevely", "wfuzz", "whatweb", "whois", "wifite",
    "windows-binaries", "winexe", "wireshark-qt", "wordlistctl", "wpscan", "zaproxy", "zdns", "zgrab2"
]

# === UTILITY FUNCTIONS ===
def clearScreen():
    os.system('clear' if os.name == 'posix' else 'cls')

def runCommand(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check)

def printBanner():
    fig = Figlet(font='slant')
    banner = fig.renderText('Black-owl')
    width = console.width if hasattr(console, "width") else 80
    for line in banner.splitlines():
        console.print(f"[bold cyan]{line.center(width)}[/bold cyan]")
    name_line = "[bold magenta]Created by[/bold magenta] [bold cyan]xdavunix[/bold cyan]"
    console.print(f"{name_line}")  
    
    
def printMainMenu():
    menu = """
[bold cyan]Main Menu:[/bold cyan]

[green]1.[/green] BlackArch Tool Categories
[green]2.[/green] Update Database
[green]3.[/green] Install BlackArch Repository
[green]4.[/green] Pentester-slim Toolset
[green]5.[/green] Generate BlackArch Menus
[green]0.[/green] Exit
"""
    console.print(Panel(menu.strip(), title="[bold blue]Select an Option[/bold blue]", border_style="cyan"))

# === PACMAN HELPERS ===
def pacmanGroupTools(group):
    try:
        result = subprocess.run(f"pacman -Sg {group}", shell=True, check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        tools = set()
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) == 2:
                tools.add(parts[1])
        return sorted(tools)
    except subprocess.CalledProcessError:
        return []

def pacmanInstalled(tool):
    result = subprocess.run(f"pacman -Q {tool}", shell=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0

def pacmanInstall(tool):
    console.print(f"[yellow]Installing [bold]{tool}[/bold] ...[/yellow]")
    runCommand(f"sudo pacman -S --noconfirm {tool}")

# === WRAPPER & DESKTOP ENTRY ===
def createWrapper(tool):
    import shlex
    wrapperPath = f"/usr/bin/{tool}-helper"
    helpText = ""
    for cmd in [
        f"{shlex.quote(tool)} --help",
        f"{shlex.quote(tool)} -h",
        f"{shlex.quote(tool)} -H",
        f"{shlex.quote(tool)} -HH",
        f"man {shlex.quote(tool)}"
    ]:
        try:
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
            if result.stdout and "not found" not in result.stdout.lower():
                filtered = "\n".join(
                    line for line in result.stdout.strip().splitlines()
                    if "illegal option" not in line.lower() and "does not exist" not in line.lower()
                )
                if filtered.strip():
                    helpText = filtered
                    break
        except Exception:
            continue
    if not helpText:
        helpText = f"No help available for {tool}."

    content = f"""#!/bin/zsh
if [ "$#" -eq 0 ] || [[ "$1" == "--help" || "$1" == "-h" || "$1" == "-H" || "$1" == "-HH" ]]; then
cat <<'EOF'
{helpText}
EOF
exit 0
fi
{tool} "$@"
echo
echo "Press Enter to close this window..."
read
"""
    proc = subprocess.Popen(['sudo', 'tee', wrapperPath], stdin=subprocess.PIPE)
    proc.communicate(input=content.encode())
    runCommand(f"sudo chmod +x {wrapperPath}")

    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
    desktopDir = os.path.expanduser(f"~{user}/.local/share/applications")
    os.makedirs(desktopDir, exist_ok=True)
    desktopPath = os.path.join(desktopDir, f"{tool}-helper.desktop")
    desktopContent = f"""[Desktop Entry]
Type=Application
Name={tool} Helper
Exec=qterminal -e zsh -i -c "/usr/bin/{tool}-helper; exec zsh"  # Change 'qterminal' and 'zsh' to match your terminal emulator and shell
Icon=utilities-terminal
Terminal=false
Categories=Utility;
"""
    with open(desktopPath, "w") as f:
        f.write(desktopContent)
    os.chmod(desktopPath, 0o755)

def batchInstallAndCreateWrappers(tools, category=None):
    for tool in tools:
        if not pacmanInstalled(tool):
            console.print(f"[yellow]Installing [bold]{tool}[/bold] ...[/yellow]")
            result = subprocess.run(f"sudo pacman -S --noconfirm {tool}", shell=True)
            if result.returncode != 0:
                console.print(f"[red]Error: target not found: {tool}[/red]")
                continue
        createWrapper(tool) 


# === MENU  ===
def confirmPrompt(prompt):
    console.print(f"[yellow]{prompt} (y/n)[/yellow]")
    while True:
        c = input().strip().lower()
        if c in ("y", "yes"):
            return True
        if c in ("n", "no"):
            return False

def toolMenu(groupKey, tools):
    while True:
        clearScreen()
        spacing, columns = 22, 4
        rows = (len(tools) + columns - 1) // columns
        lines = []
        for r in range(rows):
            line = []
            for c in range(columns):
                idx = r + c * rows
                if idx < len(tools):
                    optStr = f"{idx+1}. {tools[idx]}"
                    line.append(optStr.ljust(spacing))
            lines.append("  ".join(line))
        toolsDisplay = "\n".join(lines)
        message = (
            f"Select tools to install from '{groupKey}':\n\n"
            f"{toolsDisplay}\n\n"
            "a. Install All\n"
            "0. Cancel\nSelect multiple numbers separated by commas (e.g. 1,3,5) or 'a' for all:"
        )
        console.print(Panel(message, title="Tool Selection", border_style="magenta"))
        choice = input("Your choice: ").strip().lower()
        if choice == "0" or choice == "":
            console.print("[blue]No tools selected.[/blue]")
            input("Press Enter to continue...")
            return
        if choice == "a":
            if confirmPrompt("Install ALL tools in this category?"):
                batchInstallAndCreateWrappers(tools)  # FIX: Remove second argument
                console.print("[bold green]All tools installed.[/bold green]")
                input("Press Enter to continue...")
                return
            else:
                continue
        parts = choice.split(",")
        selected, valid = [], True
        for part in parts:
            part = part.strip()
            if part.isdigit():
                idx = int(part)
                if 1 <= idx <= len(tools):
                    selected.append(tools[idx - 1])
                else:
                    valid = False
                    break
            else:
                valid = False
                break
        if not valid or not selected:
            console.print("[red]Invalid input. Please enter valid numbers separated by commas or 'a' for all.[/red]")
            input("Press Enter to continue...")
            continue
        batchInstallAndCreateWrappers(selected)  
        console.print("[bold green]Installation(s) complete.[/bold green]")
        input("Press Enter to continue...")
        return

def categoryMenu():
    categories = list(groups.items())
    while True:
        clearScreen()
        printBanner()
        console.print("[bold magenta]Tool Categories:[/bold magenta]\n")
        for i, (key, desc) in enumerate(categories, 1):
            console.print(f"  [green]{i}.[/green] {key} [grey50]- {desc[0]}: {desc[1]}[/grey50]")
        console.print("  [green]0.[/green] Back")
        catChoice = input("\nSelect a category by number: ").strip()
        if catChoice == "0":
            return
        if not catChoice.isdigit() or not (1 <= int(catChoice) <= len(categories)):
            console.print("[red]Invalid choice. Try again.[/red]")
            input("Press Enter to continue...")
            continue
        groupKey, _ = categories[int(catChoice)-1]
        tools = pacmanGroupTools(groupKey)
        if not tools:
            console.print(f"[yellow]No tools found in {groupKey}[/yellow]")
            input("Press Enter to continue...")
            continue
        toolMenu(groupKey, tools)
        

def pentestingSlimisoMenu():
    while True:
        clearScreen()
        printBanner()
        console.print("[bold magenta]Pentesting_slim: [/bold magenta]\n")
        for i, tool in enumerate(slim_Edition, 1):
            console.print(f"  [green]{i}.[/green] {tool}")
        console.print("  [green]a.[/green] Install All")
        console.print("  [green]0.[/green] Back")
        choice = input("\nSelect tools to install (comma separated, e.g. 1,3,5), 'a' for all, or 0 to go back: ").strip().lower()
        if choice == "0" or choice == "":
            return
        if choice == "a":
            if confirmPrompt("Install ALL pentesting slim tools?"):
                batchInstallAndCreateWrappers(slim_Edition)  # FIX: Remove second argument
                console.print("[bold green]All tools installed.[/bold green]")
                input("Press Enter to continue...")
                return
            else:
                continue
        parts = choice.split(",")
        selected, valid = [], True
        for part in parts:
            part = part.strip()
            if part.isdigit():
                idx = int(part)
                if 1 <= idx <= len(slim_Edition):
                    selected.append(slim_Edition[idx - 1])
                else:
                    valid = False
                    break
            else:
                valid = False
                break
        if not valid or not selected:
            console.print("[red]Invalid input. Please enter valid numbers separated by commas or 'a' for all.[/red]")
            input("Press Enter to continue...")
            continue
        batchInstallAndCreateWrappers(selected)  
        console.print("[bold green]Installation(s) complete.[/bold green]")
        input("Press Enter to continue...")
        return
    
def updateRepo():
    console.print("[bold yellow]Updating system package database...[/bold yellow]")
    runCommand("sudo pacman -Syy --noconfirm")
    console.print("[green]Update complete.[/green]")

def installBlackarchRepo():
    console.print("[bold yellow]Installing BlackArch repository...[/bold yellow]")
    runCommand("curl -O https://blackarch.org/strap.sh")
    shaCheck = subprocess.run(
        "echo bbf0a0b838aed0ec05fff2d375dd17591cbdf8aa strap.sh | sha1sum -c",
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if "OK" not in shaCheck.stdout:
        console.print("[red]SHA1 verification failed! Aborting.[/red]")
        return
    runCommand("chmod +x strap.sh")
    runCommand("sudo ./strap.sh")
    console.print("[yellow]Please enable multilib in /etc/pacman.conf if you haven't already.[/yellow]")
    console.print("[yellow]See: https://wiki.archlinux.org/index.php/Official_repositories#Enabling_multilib[/yellow]")
    input("Press Enter to continue to full system update...")
    runCommand("sudo pacman -Syu")
    console.print("[green]BlackArch repository installation complete![/green]")
    input("Press Enter to continue...")

def generateBlackarchMenus():
    import shutil
    user = getpass.getuser()
    menuDir = os.path.expanduser(f"~{user}/.local/share/applications/BlackArch")
    os.makedirs(menuDir, exist_ok=True)
    result = subprocess.run("pacman -Qqg | grep '^blackarch-'", shell=True, stdout=subprocess.PIPE, text=True)
    toolGroups = {}
    for line in result.stdout.strip().splitlines():
        group, tool = line.split()
        toolGroups.setdefault(group, []).append(tool)
    for group, tools in toolGroups.items():
        groupName = groups.get(group, (group, ""))[0]
        for tool in tools:
            toolPath = shutil.which(tool)
            if not toolPath:
                continue
            desktopPath = os.path.join(menuDir, f"{tool}.desktop")
            desktopContent = f"""[Desktop Entry]
Type=Application
Name={tool} ({groupName})
Exec={tool}
Icon=utilities-terminal
Terminal=true
Categories=BlackArch;{group};
"""
            with open(desktopPath, "w") as f:
                f.write(desktopContent)
            os.chmod(desktopPath, 0o755)
    print(f"BlackArch menus generated in {menuDir}")

# === MAIN MENU LOOP ===
def mainMenuUnique():
    clearScreen()
    printBanner()
    try:
        runCommand("sudo -v")
    except subprocess.CalledProcessError:
        console.print("[red]You need sudo privileges to run this script.[/red]")
        sys.exit(1)

    while True:
        clearScreen()
        printBanner()
        printMainMenu()
        choice = input("Choose an option: ").strip().lower()
        if choice in ("0", "q"):
            console.print("[bold red]Exiting.[/bold red]")
            sys.exit(0)
        elif choice == "1":
            categoryMenu()
        elif choice == "2":
            (updateRepo(), input("Press Enter to continue...")) if confirmPrompt("Update system package database?") else None
        elif choice == "3":
            installBlackarchRepo() if confirmPrompt("Install BlackArch repository?") else None
        elif choice == "4":
            pentestingSlimisoMenu()
        elif choice == "5":
            generateBlackarchMenus()
            input("Press Enter to continue...")
        else:
            console.print("[red]Invalid choice. Try again.[/red]")
            input("Press Enter to continue...")

if __name__ == "__main__":
    mainMenuUnique()