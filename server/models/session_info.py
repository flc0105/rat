from dataclasses import dataclass, field


@dataclass
class SessionInfo:
    client_id: str = ''
    addr: str = ''
    hostname: str = 'Unknown'
    os_type: str = 'Unknown'
    os_ver: str = 'Unknown'
    integrity: str = '?'
    cwd: str = ''
    build_version: str = ''
    command_manifest: list[dict] = field(default_factory=list)
    system_paths: dict = field(default_factory=dict)
    extras: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict | None):
        if not isinstance(payload, dict):
            return cls()

        known_keys = {
            'id',
            'addr',
            'hostname',
            'os_type',
            'os_ver',
            'integrity',
            'cwd',
            'build_version',
            'command_manifest',
            'system_paths',
        }

        extras = {
            key: value
            for key, value in payload.items()
            if key not in known_keys
        }

        return cls(
            client_id=str(payload.get('id') or ''),
            addr=str(payload.get('addr') or ''),
            hostname=str(payload.get('hostname') or 'Unknown'),
            os_type=str(payload.get('os_type') or 'Unknown'),
            os_ver=str(payload.get('os_ver') or 'Unknown'),
            integrity=str(payload.get('integrity') or '?'),
            cwd=str(payload.get('cwd') or ''),
            build_version=(payload.get('build_version') or 'Unknown'),
            command_manifest=list(payload.get('command_manifest') or []),
            system_paths=dict(payload.get('system_paths') or {}),
            extras=extras,
        )

    def to_dict(self) -> dict:
        data = {
            'id': self.client_id,
            'addr': self.addr,
            'hostname': self.hostname,
            'os_type': self.os_type,
            'os_ver': self.os_ver,
            'integrity': self.integrity,
            'cwd': self.cwd,
            'build_version': self.build_version,
            'command_manifest': list(self.command_manifest),
            'system_paths': dict(self.system_paths),
        }
        data.update(self.extras or {})
        return data

    # add SessionInfo 兼容读取入口 2026-04-08
    def get(self, key: str, default=None):
        return self.to_dict().get(key, default)

    # add SessionInfo 额外字段读取 2026-04-08
    def get_extra(self, key: str, default=None):
        return (self.extras or {}).get(key, default)

    # add SessionInfo 额外字段写入 2026-04-08
    def set_extra(self, key: str, value):
        if self.extras is None:
            self.extras = {}
        self.extras[key] = value