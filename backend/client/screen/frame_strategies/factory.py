from client.config import runtime_config
from client.screen.frame_strategies.full_jpeg import FullJpegFrameStrategy
from client.screen.frame_strategies.keyframe_delta import KeyframeDeltaFrameStrategy
from core.utils.logger import logger


SCREEN_FRAME_STRATEGY_FULL_JPEG = 'full_jpeg'
SCREEN_FRAME_STRATEGY_KEYFRAME_DELTA = 'keyframe_delta'
SCREEN_FRAME_STRATEGIES = {
    SCREEN_FRAME_STRATEGY_FULL_JPEG: FullJpegFrameStrategy,
    SCREEN_FRAME_STRATEGY_KEYFRAME_DELTA: KeyframeDeltaFrameStrategy,
}


def get_screen_frame_strategy_name() -> str:
    value = str(getattr(runtime_config, 'SCREEN_FRAME_STRATEGY', '') or '').strip().lower()
    if value in SCREEN_FRAME_STRATEGIES:
        return value

    logger.warning(
        f'Unsupported SCREEN_FRAME_STRATEGY={value!r}; using {SCREEN_FRAME_STRATEGY_FULL_JPEG!r}'
    )
    return SCREEN_FRAME_STRATEGY_FULL_JPEG


def build_screen_frame_strategy():
    strategy_name = get_screen_frame_strategy_name()
    return SCREEN_FRAME_STRATEGIES[strategy_name]()
