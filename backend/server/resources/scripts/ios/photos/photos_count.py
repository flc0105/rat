SCRIPT_METADATA = {
    "name": "ios/recon/photo_counts",
    "display_name": "Photo Counts",
    "description": "Retrieve photo and video counts from the iOS Photos library",
    "platforms": ["ios"],
    "category": "Recon",
    "params": []
}

import json
import photos


def get_assets(media_type, include_hidden=False):
    try:
        return list(photos.get_assets(media_type=media_type, include_hidden=include_hidden))
    except TypeError:
        return list(photos.get_assets(media_type=media_type))


def count_media(media_type):
    visible_assets = get_assets(media_type, include_hidden=False)
    all_assets = get_assets(media_type, include_hidden=True)

    visible_ids = {a.local_id for a in visible_assets}
    all_ids = {a.local_id for a in all_assets}

    visible_count = len(visible_ids)
    total_count = len(all_ids)
    hidden_count = len(all_ids - visible_ids)

    return {
        "visible_count": visible_count,
        "hidden_count": hidden_count,
        "total_count": total_count,
    }


def main():
    photos_stats = count_media('image')
    videos_stats = count_media('video')

    result = {
        "photos": photos_stats,
        "videos": videos_stats
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))


main()