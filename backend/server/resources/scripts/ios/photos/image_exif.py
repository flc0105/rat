SCRIPT_METADATA = {
    "name": "ios/photos/image_exif",
    "display_name": "Image EXIF Metadata",
    "description": "Pick an image from the Photos library and extract its full EXIF metadata",
    "platforms": ["ios"],
    "category": "Photos",
    "params": []
}

import photos
import console
import json
import ctypes
from objc_util import ObjCClass, ObjCInstance, load_framework, c


load_framework("ImageIO")

NSData = ObjCClass("NSData")
NSString = ObjCClass("NSString")
NSNumber = ObjCClass("NSNumber")
NSDictionary = ObjCClass("NSDictionary")
NSArray = ObjCClass("NSArray")


CGImageSourceCreateWithData = c.CGImageSourceCreateWithData
CGImageSourceCreateWithData.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
CGImageSourceCreateWithData.restype = ctypes.c_void_p

CGImageSourceCopyPropertiesAtIndex = c.CGImageSourceCopyPropertiesAtIndex
CGImageSourceCopyPropertiesAtIndex.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
]
CGImageSourceCopyPropertiesAtIndex.restype = ctypes.c_void_p

CFRelease = c.CFRelease
CFRelease.argtypes = [ctypes.c_void_p]
CFRelease.restype = None


def nsdata_from_bytes(b):
    return NSData.dataWithBytes_length_(b, len(b))


def objc_to_py(obj):
    if obj is None:
        return None

    if isinstance(obj, int):
        obj = ObjCInstance(obj)

    if obj.isKindOfClass_(NSString):
        return str(obj)

    if obj.isKindOfClass_(NSNumber):
        s = str(obj.stringValue())
        try:
            return int(s)
        except Exception:
            try:
                return float(s)
            except Exception:
                return s

    if obj.isKindOfClass_(NSArray):
        return [objc_to_py(obj.objectAtIndex_(i)) for i in range(obj.count())]

    if obj.isKindOfClass_(NSDictionary):
        d = {}
        keys = obj.allKeys()
        for i in range(keys.count()):
            k = keys.objectAtIndex_(i)
            v = obj.objectForKey_(k)
            d[str(k)] = objc_to_py(v)
        return d

    return str(obj)


def get_full_metadata(asset):
    data = asset.get_image_data(original=True)
    raw = data.getvalue()

    nsdata = nsdata_from_bytes(raw)
    source = CGImageSourceCreateWithData(nsdata.ptr, None)

    if not source:
        raise RuntimeError("CGImageSourceCreateWithData failed")

    props = None

    try:
        props = CGImageSourceCopyPropertiesAtIndex(source, 0, None)

        if not props:
            raise RuntimeError("CGImageSourceCopyPropertiesAtIndex failed")

        return objc_to_py(props)

    finally:
        if props:
            CFRelease(props)
        if source:
            CFRelease(source)


def main():
    console.clear()

    asset = photos.pick_asset(title="Pick image", multi=False)

    if not asset:
        print("Cancelled")
        return

    metadata = get_full_metadata(asset)

    print(json.dumps(
        metadata,
        ensure_ascii=False,
        indent=2,
        sort_keys=True
    ))


if __name__ == "__main__":
    main()
