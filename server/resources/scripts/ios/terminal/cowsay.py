SCRIPT_METADATA = {
    "name": "common/terminal/cowsay",
    "display_name": "Cowsay",
    "description": "Generate ASCII art cow speaking a message or fortune, with customizable eyes and tongue",
    "platforms": ["common"],
    "category": "Terminal",
    "params": [
        {
            "name": "text",
            "type": "string",
            "required": False,
            "default": "",
            "description": "Message for the cow to say (random fortune if empty)"
        },
        {
            "name": "mode",
            "type": "select",
            "required": False,
            "default": "say",
            "options": ["say", "think"],
            "description": "Speech bubble style: say (< >) or think (( ))"
        },
        {
            "name": "eyes",
            "type": "string",
            "required": False,
            "default": "oo",
            "description": "Cow's eyes (e.g., oo, xx, $$, @@)"
        },
        {
            "name": "tongue",
            "type": "string",
            "required": False,
            "default": "  ",
            "description": "Cow's tongue (e.g., '  ', 'U ', '||')"
        },
        {
            "name": "max_width",
            "type": "number",
            "required": False,
            "default": 40,
            "description": "Maximum width of the speech bubble"
        }
    ]
}

# coding: utf-8
import random
import unicodedata


FORTUNES = [
    "The quieter you become, the more you are able to hear.",
    "There is no cloud. It's just someone else's computer.",
    "Never test for an error condition you don't know how to handle.",
    "It works on my machine.",
    "Simplicity is prerequisite for reliability.",
    "古老的程序员从不死去,只是变成了后台进程。",
    "能跑就别动,能动就别重构。",
    "今天的 bug,是明天的 feature。",
]


def char_width(ch):
    """返回字符在等宽终端里的显示宽度。中文通常算 2。"""
    if unicodedata.combining(ch):
        return 0
    if unicodedata.east_asian_width(ch) in ("F", "W"):
        return 2
    return 1


def text_width(s):
    """计算字符串显示宽度。"""
    return sum(char_width(ch) for ch in s)


def pad_to_width(s, width):
    """按显示宽度补空格。"""
    return s + " " * max(0, width - text_width(s))


def wrap_line(line, max_width):
    """按显示宽度换行,兼容中文。"""
    if max_width <= 0:
        return [line]

    result = []
    buf = ""
    buf_width = 0

    for ch in line:
        w = char_width(ch)

        if buf and buf_width + w > max_width:
            result.append(buf)
            buf = ch
            buf_width = w
        else:
            buf += ch
            buf_width += w

    result.append(buf)
    return result


def wrap_text(text, max_width=40):
    """保留原始换行,同时对过长行自动换行。"""
    lines = []

    for raw_line in str(text).splitlines() or [""]:
        lines.extend(wrap_line(raw_line, max_width))

    return lines


def make_bubble(text, max_width=40, mode="say"):
    """
    生成 cowsay 气泡。
    mode:
      say   -> < >
      think -> ( )
    """
    lines = wrap_text(text, max_width=max_width)
    width = max(text_width(line) for line in lines) if lines else 0

    out = []
    out.append(" " + "_" * (width + 2))

    if len(lines) == 1:
        line = " " + pad_to_width(lines[0], width) + " "
        if mode == "think":
            out.append("( {} )".format(pad_to_width(lines[0], width)))
        else:
            out.append("<{}>".format(line))
    else:
        for i, line in enumerate(lines):
            padded = " " + pad_to_width(line, width) + " "

            if mode == "think":
                left, right = "(", ")"
            else:
                if i == 0:
                    left, right = "/", "\\"
                elif i == len(lines) - 1:
                    left, right = "\\", "/"
                else:
                    left, right = "|", "|"

            out.append(left + padded + right)

    out.append(" " + "-" * (width + 2))
    return "\n".join(out)


def cow_art(eyes="oo", tongue="  ", mode="say"):
    lead = "o" if mode == "think" else "\\"

    return r"""        {lead}   ^__^
         {lead}  ({eyes})\_______
            (__)\       )\/\
             {tongue} ||----w |
                ||     ||""".format(
        lead=lead,
        eyes=eyes,
        tongue=tongue,
    )


def cowsay(
    text,
    max_width=40,
    mode="say",
    eyes="oo",
    tongue="  ",
):
    """
    返回完整 cowsay 字符串。

    mode: say / think
    """
    bubble = make_bubble(text, max_width=max_width, mode=mode)
    art = cow_art(eyes=eyes, tongue=tongue, mode=mode)

    return bubble + "\n" + art


def fortune():
    return random.choice(FORTUNES)


if __name__ == "__main__":
    text = kwargs.get('text', '').strip()
    if not text:
        text = fortune()
    mode = kwargs.get('mode', 'say')
    eyes = kwargs.get('eyes', 'oo')
    tongue = kwargs.get('tongue', '  ')
    max_width = kwargs.get('max_width', 40)

    print(cowsay(text, max_width=max_width, mode=mode, eyes=eyes, tongue=tongue))