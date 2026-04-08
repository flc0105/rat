import os


class WebAgentApi:
    """
    Web Agent 子外观。

    职责：
    - 提供 Agent build 能力
    - 提供构建产物定位能力
    - 提供构建临时目录清理能力
    """

    def __init__(self, agent_builder):
        self.agent_builder = agent_builder

    def build_agent(
        self,
        server_host: str,
        server_port: int,
        web_port: int = None,
        target_os: str = 'mac',
        builder: str = 'pyinstaller',
        target_arch: str = 'auto',
    ):
        return self.agent_builder.build_agent(
            server_host=server_host,
            server_port=server_port,
            web_port=web_port,
            target_os=target_os,
            builder=builder,
            target_arch=target_arch,
        )

    def get_built_agent_file_path(self, filename: str):
        file_path = os.path.join(self.agent_builder.output_dir, filename)
        if not os.path.isfile(file_path):
            raise FileNotFoundError('File not found')
        return file_path

    def cleanup_agent_build(self, work_dir: str):
        if work_dir:
            self.agent_builder.cleanup_build_dir(work_dir)
        return {'cleaned': True}