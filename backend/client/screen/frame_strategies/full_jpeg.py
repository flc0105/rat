from client.screen.frame_strategies.base import ScreenFrameStrategy


class FullJpegFrameStrategy(ScreenFrameStrategy):
    """保留原有整屏 JPEG 编码与传输行为。"""

    name = 'full_jpeg'

    def __init__(self):
        self._seq = 0

    def encode(self, image, quality: int):
        image = self._prepare_rgb(image)
        frame_bytes = self._encode_jpeg(image, quality)
        self._seq += 1

        return {
            'strategy': self.name,
            'frame_type': 'full',
            'frame_seq': self._seq,
            'base_seq': self._seq,
            'data': frame_bytes,
            'width': int(image.width),
            'height': int(image.height),
            'patch_x': 0,
            'patch_y': 0,
            'patch_width': int(image.width),
            'patch_height': int(image.height),
        }
