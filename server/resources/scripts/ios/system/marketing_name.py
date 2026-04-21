SCRIPT_METADATA = {
    "name": "apple/recon/device_model",
    "display_name": "Apple Device Model",
    "description": "Detect Apple device hardware identifier and marketing name on iOS and macOS",
    "platforms": ["ios", "macos"],
    "category": "Recon",
    "params": []
}

import ctypes
import json
import platform


IOS_MARKETING_NAME_MAP = {
    "iPhone17,1": "iPhone 16 Pro",
    "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,3": "iPhone 16",
    "iPhone17,4": "iPhone 16 Plus",
    "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus",
    "iPhone15,2": "iPhone 14 Pro",
    "iPhone15,3": "iPhone 14 Pro Max",
    "iPhone14,7": "iPhone 14",
    "iPhone14,8": "iPhone 14 Plus",
    "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,4": "iPhone 13 mini",
    "iPhone14,5": "iPhone 13",
    "iPhone14,6": "iPhone SE (3rd generation)",
    "iPad16,3": "iPad Pro 11-inch (M4)",
    "iPad16,4": "iPad Pro 11-inch (M4)",
    "iPad16,5": "iPad Pro 13-inch (M4)",
    "iPad16,6": "iPad Pro 13-inch (M4)",
    "iPad14,8": "iPad Air 11-inch (M2)",
    "iPad14,9": "iPad Air 11-inch (M2)",
    "iPad14,10": "iPad Air 13-inch (M2)",
    "iPad14,11": "iPad Air 13-inch (M2)",
    "iPad14,1": "iPad mini (6th generation)",
    "iPad14,2": "iPad mini (6th generation)",
    "iPad13,16": "iPad Air (5th generation)",
    "iPad13,17": "iPad Air (5th generation)",
    "iPad13,18": "iPad (10th generation)",
    "iPad13,19": "iPad (10th generation)",
}

MAC_MARKETING_NAME_MAP = {
    "MacBookPro18,1": "MacBook Pro (16-inch, 2021)",
    "MacBookPro18,2": "MacBook Pro (16-inch, 2021)",
    "MacBookPro18,3": "MacBook Pro (14-inch, 2021)",
    "MacBookPro18,4": "MacBook Pro (14-inch, 2021)",
    "Mac14,2": "MacBook Air (13-inch, M2, 2022)",
    "Mac14,5": "MacBook Air (15-inch, M2, 2023)",
    "Mac14,7": "MacBook Pro (13-inch, M2, 2022)",
    "Mac15,3": "MacBook Pro (14-inch, Nov 2023)",
    "Mac15,6": "MacBook Pro (14-inch, Nov 2023)",
    "Mac15,8": "MacBook Pro (14-inch, Nov 2023)",
    "Mac15,7": "MacBook Pro (16-inch, Nov 2023)",
    "Mac15,9": "MacBook Pro (16-inch, Nov 2023)",
    "Mac15,10": "MacBook Pro (16-inch, Nov 2023)",
    "Mac15,12": "MacBook Air (13-inch, M3, 2024)",
    "Mac15,13": "MacBook Air (15-inch, M3, 2024)",
}


def sysctl_string(name: str) -> str:
    libc = ctypes.CDLL(None)
    size = ctypes.c_size_t()

    result = libc.sysctlbyname(
        name.encode("utf-8"),
        None,
        ctypes.byref(size),
        None,
        0,
    )
    if result != 0 or size.value <= 0:
        return ""

    buf = ctypes.create_string_buffer(size.value)
    result = libc.sysctlbyname(
        name.encode("utf-8"),
        buf,
        ctypes.byref(size),
        None,
        0,
    )
    if result != 0:
        return ""

    return buf.value.decode("utf-8", errors="replace").strip("\x00").strip()


def detect_apple_identifier() -> str:
    machine = sysctl_string("hw.machine")
    model = sysctl_string("hw.model")

    # iOS / iPadOS 优先 hw.machine，如 iPhone17,3 / iPad14,8
    if machine.startswith(("iPhone", "iPad")):
        return machine

    # macOS 优先 hw.model，如 MacBookPro18,3
    if model.startswith(("MacBook", "Mac")):
        return model

    # 某些 Apple Silicon Mac 上 hw.machine 可能是 arm64，不适合做 marketing name 映射
    # 这里只作为最后兜底展示
    return model or machine or platform.machine()


def lookup_apple_marketing_name(identifier: str) -> str:
    if identifier.startswith(("iPhone", "iPad")):
        return IOS_MARKETING_NAME_MAP.get(identifier, "")
    if identifier.startswith(("MacBook", "Mac")):
        return MAC_MARKETING_NAME_MAP.get(identifier, "")
    return ""


def build_apple_marketing_name_payload() -> dict:
    identifier = detect_apple_identifier()
    marketing_name = lookup_apple_marketing_name(identifier)

    return {
        "identifier": identifier,
        "marketing_name": marketing_name,
        "is_known": bool(marketing_name),
    }


print(json.dumps(build_apple_marketing_name_payload(), ensure_ascii=False, indent=2))