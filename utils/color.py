RESET = '\033[0m'
BOLD = '\033[01m'
DISABLE = '\033[02m'
UNDERLINE = '\033[04m'
REVERSE = '\033[07m'
STRIKE_THROUGH = '\033[09m'
INVISIBLE = '\033[08m'

FG_BLACK = '\033[30m'
FG_RED = '\033[31m'
FG_GREEN = '\033[32m'
FG_ORANGE = '\033[33m'
FG_BLUE = '\033[34m'
FG_PURPLE = '\033[35m'
FG_CYAN = '\033[36m'
FG_LIGHT_GREY = '\033[37m'
FG_DARK_GREY = '\033[90m'
FG_LIGHT_RED = '\033[91m'
FG_LIGHT_GREEN = '\033[92m'
FG_YELLOW = '\033[93m'
FG_LIGHT_BLUE = '\033[94m'
FG_PINK = '\033[95m'
FG_LIGHT_CYAN = '\033[96m'

BG_BLACK = '\033[40m'
BG_RED = '\033[41m'
BG_GREEN = '\033[42m'
BG_ORANGE = '\033[43m'
BG_BLUE = '\033[44m'
BG_PURPLE = '\033[45m'
BG_CYAN = '\033[46m'
BG_LIGHT_GREY = '\033[47m'


def draw(text, bold=False, underline=False, strike_through=False, disable=False, reverse=False, invisible=False,
         fg_black=False, fg_red=False, fg_green=False, fg_orange=False, fg_blue=False, fg_purple=False, fg_cyan=False, fg_light_grey=False, fg_dark_grey=False, fg_light_red=False, fg_light_green=False, fg_yellow=False, fg_light_blue=False, fg_pink=False, fg_light_cyan=False,
         bg_black=False, bg_red=False, bg_green=False, bg_orange=False, bg_blue=False, bg_purple=False, bg_cyan=False, bg_light_grey=False):
    style = ''

    if not isinstance(text, str):
        text = str(text)
        
    if bold:
        style += BOLD
    if disable:
        style += DISABLE
    if underline:
        style += UNDERLINE
    if reverse:
        style += REVERSE
    if strike_through:
        style += STRIKE_THROUGH
    if invisible:
        style += INVISIBLE
    if fg_black:
        style += FG_BLACK
    if fg_red:
        style += FG_RED
    if fg_green:
        style += FG_GREEN
    if fg_orange:
        style += FG_ORANGE
    if fg_blue:
        style += FG_BLUE
    if fg_purple:
        style += FG_PURPLE
    if fg_cyan:
        style += FG_CYAN
    if fg_light_grey:
        style += FG_LIGHT_GREY
    if fg_dark_grey:
        style += FG_DARK_GREY
    if fg_light_red:
        style += FG_LIGHT_RED
    if fg_light_green:
        style += FG_LIGHT_GREEN
    if fg_yellow:
        style += FG_YELLOW
    if fg_light_blue:
        style += FG_LIGHT_BLUE
    if fg_pink:
        style += FG_PINK
    if fg_light_cyan:
        style += FG_LIGHT_CYAN
    if bg_black:
        style += BG_BLACK
    if bg_red:
        style += BG_RED
    if bg_green:
        style += BG_GREEN
    if bg_orange:
        style += BG_ORANGE
    if bg_blue:
        style += BG_BLUE
    if bg_purple:
        style += BG_PURPLE
    if bg_cyan:
        style += BG_CYAN
    if bg_light_grey:
        style += BG_LIGHT_GREY

    if style:
        text = style + text + RESET

    return text


def error(text):
    return draw(text, bold=True, fg_red=True)


def warning(text):
    return draw(text, bold=True, fg_orange=True)


def success(text):
    return draw(text, fg_green=True)


