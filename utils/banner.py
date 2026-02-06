"""Banner and branding utilities"""

from utils.colors import Colors
import os


def print_banner():
    """Print panda banner from banner.txt with tool credits"""
    try:
        # Try to load panda banner from file
        banner_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'banner.txt')
        if os.path.exists(banner_path):
            with open(banner_path, 'r') as f:
                panda = f.read()
            
            banner = f"""{Colors.BRIGHT_CYAN}{panda}
{Colors.RESET}{Colors.BOLD}{Colors.CYAN}
Web Security Scanner - Built by Spidey & Clay Group
Instagram: @exp1oit | @h4cker.in
Telegram: @spideyapk | @spideyze
{Colors.RESET}
"""
        else:
            # Fallback if banner.txt not found
            banner = f"""
{Colors.BOLD}{Colors.CYAN}
Web Security Scanner - Built by Spidey & Clay Group
Instagram: @exp1oit | @h4cker.in
Telegram: @spideyapk | @spideyze
{Colors.RESET}
"""
    except Exception as e:
        # Fallback in case of any error
        banner = f"""
{Colors.BOLD}{Colors.CYAN}
Web Security Scanner - Built by Spidey & Clay Group
Instagram: @exp1oit | @h4cker.in
Telegram: @spideyapk | @spideyze
{Colors.RESET}
"""
    print(banner)


def print_footer():
    """Print footer with credits and donation info"""
    footer = f"""
{Colors.CYAN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.BOLD}YAHA - Ethical Web Security Scanner{Colors.RESET}{Colors.CYAN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{Colors.BOLD}Made with ❤️  by:{Colors.RESET}{Colors.CYAN}
  • Spidey (@spideyze on Telegram)
  • Clay (@exp1oit on Instagram)
  • Crew: @h4cker.in (Telegram)

{Colors.BOLD}Support Development:{Colors.RESET}{Colors.CYAN}
  Bitcoin: 1A1z7agoat2rwCC5Kj1tN7SbLFy5g516b2
  (Donations fuel future features & research)

{Colors.BOLD}Remember:{Colors.RESET}{Colors.CYAN}
  • Use only for authorized security testing
  • Always get written permission before scanning
  • This tool is for educational purposes
  • Misuse is illegal and unethical

{Colors.BOLD}Resources:{Colors.RESET}{Colors.CYAN}
  • GitHub: (Coming soon)
  • Discord: (Community channel)
  • Docs: https://github.com/spideyze/yaha

{Colors.BOLD}Stay ethical. Stay legal. Stay secure.{Colors.RESET}{Colors.CYAN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.RESET}
"""
    print(footer)
