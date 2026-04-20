from objc_util import *

NSBundle.bundleWithPath_('/System/Library/Frameworks/MediaPlayer.framework').load()
MPMediaQuery = ObjCClass('MPMediaQuery')
query = MPMediaQuery.songsQuery()

for item in query.items():
	artist = str(item.valueForKey_('artist'))
	title = str(item.valueForKey_('title'))
	print(artist + ' - ' + title)
