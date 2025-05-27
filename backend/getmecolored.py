tclr: dict[str, str] = {
    'GOOD': '\033[1;32m{0}\033[0m',
    'WARN': '\033[33m{0}\033[0m',
    'FAIL': '\033[1;31m{0}\033[0m',
    'INFO': '\033[96m{0}\033[0m'
}

def color_me(data: str, color: int) -> str:
    return f'\033[{color}m' + data + '\033[0m'

def good(data: str) -> str: return tclr['GOOD'].format(data)
def warn(data: str) -> str: return tclr['WARN'].format(data)
def fail(data: str) -> str: return tclr['FAIL'].format(data)
def info(data: str) -> str: return tclr['INFO'].format(data)

def pref_good() -> str:
    """
    Test for documentation
    :return: Return string OK colored for more comfortable log analyzing
    """
    return f"[{good(data='OK')}]\t"
def pref_warn() -> str: return f"[{warn(data='WARN')}]\t"
def pref_fail() -> str: return f"[{fail(data='FAIL')}]\t"
def pref_info() -> str: return f"[{info(data='INFO')}]\t"