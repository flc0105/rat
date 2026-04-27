SCRIPT_METADATA = {
    "name": "ios/music/apple_music_now_playing",
    "display_name": "Apple Music Now Playing",
    "description": "Retrieve currently playing media information from the iOS Music app",
    "platforms": ["ios"],
    "category": "Recon",
    "params": []
}

from objc_util import *
from ctypes import c_void_p

load_framework('MediaPlayer')

MPMusicPlayerController = ObjCClass('MPMusicPlayerController')

def msg_obj_0(obj, selector_name):
    c.objc_msgSend.restype = c_void_p
    c.objc_msgSend.argtypes = [c_void_p, c_void_p]
    p = c.objc_msgSend(obj.ptr, sel(selector_name))
    return ObjCInstance(p) if p else None

def msg_obj_1(obj, selector_name, arg):
    c.objc_msgSend.restype = c_void_p
    c.objc_msgSend.argtypes = [c_void_p, c_void_p, c_void_p]
    arg_ptr = arg.ptr if hasattr(arg, 'ptr') else arg
    p = c.objc_msgSend(obj.ptr, sel(selector_name), arg_ptr)
    return ObjCInstance(p) if p else None

def get_now_playing():
    player = MPMusicPlayerController.systemMusicPlayer()
    item = player.nowPlayingItem()

    info = {
        'state': int(player.playbackState()),
        'title': None,
        'artist': None,
        'album': None,
    }

    if item:
        info['title'] = str(msg_obj_0(item, 'title') or '')
        info['artist'] = str(msg_obj_0(item, 'artist') or '')
        info['album'] = str(msg_obj_0(item, 'albumTitle') or '')

    return info

info = get_now_playing()
print(info)