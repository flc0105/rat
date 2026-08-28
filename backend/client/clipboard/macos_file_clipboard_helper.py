import os
import sys

from AppKit import NSPasteboard
from Foundation import NSURL


def main():
    paths = [os.path.abspath(path) for path in sys.argv[1:] if path]
    if not paths:
        raise ValueError('No clipboard files were provided')

    for path in paths:
        if not os.path.exists(path):
            raise FileNotFoundError(f'Clipboard file does not exist: {path}')

    urls = [NSURL.fileURLWithPath_(path) for path in paths]
    pasteboard = NSPasteboard.generalPasteboard()
    pasteboard.clearContents()

    if not pasteboard.writeObjects_(urls):
        raise RuntimeError('Failed to write file URLs to macOS clipboard')


if __name__ == '__main__':
    main()