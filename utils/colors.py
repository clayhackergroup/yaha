"""Color and formatting utilities"""


class Colors:
    """ANSI color codes for terminal output"""
    
    # Text colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Formatting
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    
    # Combinations
    BRIGHT_RED = f'{BOLD}{RED}'
    BRIGHT_GREEN = f'{BOLD}{GREEN}'
    BRIGHT_YELLOW = f'{BOLD}{YELLOW}'
    BRIGHT_BLUE = f'{BOLD}{BLUE}'
    BRIGHT_CYAN = f'{BOLD}{CYAN}'


class Styling:
    """Text styling utilities"""
    
    @staticmethod
    def success(text):
        return f"{Colors.GREEN}✓ {text}{Colors.RESET}"
    
    @staticmethod
    def warning(text):
        return f"{Colors.YELLOW}⚠ {text}{Colors.RESET}"
    
    @staticmethod
    def error(text):
        return f"{Colors.RED}✗ {text}{Colors.RESET}"
    
    @staticmethod
    def info(text):
        return f"{Colors.CYAN}ℹ {text}{Colors.RESET}"
