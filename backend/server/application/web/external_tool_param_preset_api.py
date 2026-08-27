class WebExternalToolParamPresetApi:
    """ExternalTool module parameter preset web API."""

    def __init__(self, catalog_service, preset_store):
        self.catalog_service = catalog_service
        self.preset_store = preset_store

    def _module_param_names(self, tool_id: str) -> set[str]:
        module = self.catalog_service.get_module(tool_id)
        return {
            str(item.get('name') or '').strip()
            for item in (module.get('params') or [])
            if str(item.get('name') or '').strip()
        }

    def _validate_params(self, tool_id: str, params) -> dict:
        if not isinstance(params, dict):
            raise ValueError('params must be an object')
        allowed_names = self._module_param_names(tool_id)
        unknown = sorted(str(name) for name in params.keys() if str(name) not in allowed_names)
        if unknown:
            raise ValueError(f'Unknown params for {tool_id}: {", ".join(unknown)}')
        return dict(params)

    def list_presets(self, tool_id: str):
        self._module_param_names(tool_id)
        return {
            'tool_id': tool_id,
            'items': self.preset_store.list_presets(tool_id),
        }

    def create_preset(self, tool_id: str, name: str, params):
        validated_params = self._validate_params(tool_id, params)
        return self.preset_store.create_preset(tool_id, name, validated_params)

    def update_preset(self, tool_id: str, preset_id: str, name: str = '', params=None):
        validated_params = None if params is None else self._validate_params(tool_id, params)
        return self.preset_store.update_preset(
            tool_id,
            preset_id,
            name=name,
            params=validated_params,
        )

    def delete_preset(self, tool_id: str, preset_id: str):
        self._module_param_names(tool_id)
        return self.preset_store.delete_preset(tool_id, preset_id)
