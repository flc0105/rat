SCRIPT_METADATA = {
    "name": "ios/recon/list_albums",
    "display_name": "List Albums",
    "description": "Retrieve all photo albums with photo counts from the iOS Photos library",
    "platforms": ["ios"],
    "category": "Recon",
    "params": []
}

import json
import photos


def safe_count(album):
    try:
        return len(album.assets)
    except Exception:
        return -1


def collect_rows():
    rows = []

    try:
        regular_albums = list(photos.get_albums())
    except Exception:
        regular_albums = []

    try:
        smart_albums = list(photos.get_smart_albums())
    except Exception:
        smart_albums = []

    regular_rows = []
    for album in regular_albums:
        regular_rows.append({
            "type": "regular",
            "name": str(album.title or ""),
            "photos_count": safe_count(album),
        })

    smart_rows = []
    for album in smart_albums:
        smart_rows.append({
            "type": "smart",
            "name": str(album.title or ""),
            "photos_count": safe_count(album),
        })

    regular_rows.sort(key=lambda x: x["name"].casefold())
    smart_rows.sort(key=lambda x: x["name"].casefold())

    rows.extend(regular_rows)
    rows.extend(smart_rows)
    return rows


def main():
    rows = collect_rows()
    print(json.dumps(rows, ensure_ascii=False, indent=2))


main()