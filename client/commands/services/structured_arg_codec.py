import base64
import json


class StructuredArgCodec:
    """
    命令结构化参数编解码服务。
    """

    JSON_PREFIX = '__json__:'

    def strip_wrapped_quotes(self, value: str) -> str:
        text = (value or '').strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
            return text[1:-1]
        return text

    def decode(self, raw):
        text = self.strip_wrapped_quotes(raw)
        if not text:
            return ''

        if text.startswith(self.JSON_PREFIX):
            encoded = text[len(self.JSON_PREFIX):]
            decoded = base64.urlsafe_b64decode(encoded.encode()).decode('utf-8')
            return json.loads(decoded)

        return text

    def extract_path(self, raw) -> str:
        value = self.decode(raw)
        if isinstance(value, dict):
            return (value.get('path') or '').strip()
        return (value or '').strip()