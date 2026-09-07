import io


class ScreenFrameStrategy:
    """Screen View 帧编码策略基类。"""

    name = ''

    def encode(self, image, quality: int):
        raise NotImplementedError

    def _prepare_rgb(self, image):
        if image is None:
            raise RuntimeError('Screen capture returned no image')
        if getattr(image, 'mode', '') != 'RGB':
            return image.convert('RGB')
        return image

    def _encode_jpeg(self, image, quality: int) -> bytes:
        buffer = io.BytesIO()
        image.save(
            buffer,
            format='JPEG',
            quality=int(quality),
            optimize=False,
        )
        return buffer.getvalue()
