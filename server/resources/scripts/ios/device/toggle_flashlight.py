SCRIPT_METADATA = {
    "name": "ios/device/toggle_flashlight",
    "display_name": "Toggle Flashlight",
    "description": "Toggle the device flashlight on or off",
    "platforms": ["ios"],
    "category": "Device",
    "params": []
}

from objc_util import ObjCClass

def toggle_flashlight():
	AVCaptureDevice = ObjCClass('AVCaptureDevice')
	device = AVCaptureDevice.defaultDeviceWithMediaType_('vide')
	if not device.hasTorch():
		raise RuntimeError('Device has no flashlight')
	mode = device.torchMode()
	device.lockForConfiguration_(None)
	device.setTorchMode_((mode + 1) % 2)
	device.unlockForConfiguration()
	
toggle_flashlight()
