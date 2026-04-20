#!/usr/bin/env python3
# coding: utf-8

import argparse
import photos


def all_assets_map(include_hidden=False):
    """
    返回 {local_id: asset}
    """
    try:
        assets = photos.get_assets(media_type='image', include_hidden=include_hidden)
    except TypeError:
        # 兼容旧版本接口
        assets = photos.get_assets(media_type='image')
    return {a.local_id: a for a in assets}


def hidden_id_set():
    """
    获取全库隐藏图片的 local_id 集合
    """
    try:
        visible = all_assets_map(include_hidden=False)
        all_imgs = all_assets_map(include_hidden=True)
        return set(all_imgs.keys()) - set(visible.keys())
    except Exception:
        return set()


def safe_len_assets(album):
    try:
        return len(album.assets)
    except Exception:
        return -1


def count_hidden_in_album(album, hidden_ids):
    try:
        return sum(1 for a in album.assets if a.local_id in hidden_ids)
    except Exception:
        return -1


def collect_rows(show_regular=True, show_smart=True, show_moments=False, show_hidden=False):
    rows = []

    hidden_ids = hidden_id_set() if show_hidden else set()

    if show_regular:
        for album in photos.get_albums():
            total = safe_len_assets(album)
            hidden = count_hidden_in_album(album, hidden_ids) if show_hidden else None
            rows.append({
                'group': 'regular',
                'path': f'regular/{album.title}',
                'title': album.title,
                'count': total,
                'hidden': hidden,
            })

    if show_smart:
        try:
            for album in photos.get_smart_albums():
                total = safe_len_assets(album)
                hidden = count_hidden_in_album(album, hidden_ids) if show_hidden else None
                rows.append({
                    'group': 'smart',
                    'path': f'smart/{album.title}',
                    'title': album.title,
                    'count': total,
                    'hidden': hidden,
                })
        except Exception:
            pass

    if show_moments:
        try:
            for album in photos.get_moments():
                total = safe_len_assets(album)
                hidden = count_hidden_in_album(album, hidden_ids) if show_hidden else None
                rows.append({
                    'group': 'moment',
                    'path': f'moment/{album.title}',
                    'title': album.title,
                    'count': total,
                    'hidden': hidden,
                })
        except Exception:
            pass

    return rows


def format_num(n):
    return '?' if n is None or n < 0 else str(n)


def main():
    parser = argparse.ArgumentParser(description='List photo albums with counts')
    parser.add_argument('--sort', choices=['name', 'count', 'hidden', 'group'], default='name')
    parser.add_argument('--reverse', action='store_true')

    parser.add_argument('--show-hidden', action='store_true',
                        help='显示每个相册中估算的隐藏图片数量')
    parser.add_argument('--show-moments', action='store_true',
                        help='把 moments 也列出来')
    parser.add_argument('--regular-only', action='store_true')
    parser.add_argument('--smart-only', action='store_true')
    parser.add_argument('--path-only', action='store_true',
                        help='只输出 path 风格名称')
    args = parser.parse_args()

    show_regular = True
    show_smart = True
    if args.regular_only:
        show_smart = False
    if args.smart_only:
        show_regular = False

    rows = collect_rows(
        show_regular=show_regular,
        show_smart=show_smart,
        show_moments=args.show_moments,
        show_hidden=args.show_hidden,
    )

    if args.sort == 'count':
        rows.sort(key=lambda x: (x['count'] if x['count'] >= 0 else -1, x['path'].lower()),
                  reverse=args.reverse)
    elif args.sort == 'hidden':
        rows.sort(key=lambda x: (x['hidden'] if isinstance(x['hidden'], int) else -1, x['path'].lower()),
                  reverse=args.reverse)
    elif args.sort == 'group':
        rows.sort(key=lambda x: (x['group'], x['path'].lower()), reverse=args.reverse)
    else:
        rows.sort(key=lambda x: x['path'].lower(), reverse=args.reverse)

    total_albums = len(rows)
    total_assets = 0
    total_hidden = 0

    if args.path_only:
        for r in rows:
            print(r['path'])
        return

    if args.show_hidden:
        print(f'{"COUNT":>8}  {"HIDDEN":>8}  PATH')
        print('-' * 60)
        for r in rows:
            print(f'{format_num(r["count"]):>8}  {format_num(r["hidden"]):>8}  {r["path"]}')
            if r['count'] >= 0:
                total_assets += r['count']
            if isinstance(r['hidden'], int) and r['hidden'] >= 0:
                total_hidden += r['hidden']
        print('-' * 60)
        print(f'albums: {total_albums}')
        print(f'assets(sum): {total_assets}')
        print(f'hidden(sum): {total_hidden}')
    else:
        print(f'{"COUNT":>8}  PATH')
        print('-' * 60)
        for r in rows:
            print(f'{format_num(r["count"]):>8}  {r["path"]}')
            if r['count'] >= 0:
                total_assets += r['count']
        print('-' * 60)
        print(f'albums: {total_albums}')
        print(f'assets(sum): {total_assets}')


main()
