SCRIPT_METADATA = {
    "name": "ios/recon/cpu_arch",
    "display_name": "CPU Architecture",
    "description": "Detect CPU architecture (arm64 or legacy) on iOS and macOS devices",
    "platforms": ["ios", "macos"],
    "category": "Recon",
    "params": []
}

def detect_ios_arch() -> str:
    try:
        import ctypes

        libc = ctypes.CDLL(None)
        size = ctypes.c_size_t(ctypes.sizeof(ctypes.c_int))
        value = ctypes.c_int()

        result = libc.sysctlbyname(
            b'hw.optional.arm64',
            ctypes.byref(value),
            ctypes.byref(size),
            None,
            0,
        )
        if result == 0 and value.value == 1:
            return 'arm64'
    except Exception:
        pass

    return 'na'

print(detect_ios_arch())