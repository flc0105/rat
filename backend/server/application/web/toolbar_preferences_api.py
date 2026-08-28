class WebToolbarPreferencesApi:
    """Toolbar UI 偏好 Web 子外观。"""

    def __init__(self, preference_store):
        self.preference_store = preference_store

    def get_preferences(self):
        return self.preference_store.get_preferences()

    def save_preferences(self, payload: dict):
        return self.preference_store.save_preferences(payload or {})
