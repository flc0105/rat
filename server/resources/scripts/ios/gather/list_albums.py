#!/usr/bin/env python3
# coding: utf-8

import argparse
import photos


def main():
    parser = argparse.ArgumentParser(description='List albums with asset counts')
    parser.add_argument('--sort', choices=['name', 'count'], default='name')
    parser.add_argument('--reverse', action='store_true')
    args = parser.parse_args()

    rows = []
    for album in photos.get_albums():
        try:
            count = len(album.assets)
        except Exception:
            count = -1
        rows.append((album.title, count))

    if args.sort == 'count':
        rows.sort(key=lambda x: (x[1], x[0].lower()), reverse=args.reverse)
    else:
        rows.sort(key=lambda x: x[0].lower(), reverse=args.reverse)

    total = 0
    for title, count in rows:
        c = '?' if count < 0 else str(count)
        print(f'{c.rjust(6)}  {title}')
        if count >= 0:
            total += count

    print(f'\nalbums: {len(rows)}')
    print(f'assets(sum of listed albums): {total}')


main()
