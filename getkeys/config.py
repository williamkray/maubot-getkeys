from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper


class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        helper.copy("command_prefix")
        helper.copy("admins")
        helper.copy("permissions.allowed_users")
        helper.copy("permissions.min_power_level")
        helper.copy("blocked_rooms")
        helper.copy("cooldown_seconds")
        helper.copy("dm_join_timeout")
        helper.copy("pbkdf2_rounds")
