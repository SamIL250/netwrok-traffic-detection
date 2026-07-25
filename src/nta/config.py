from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "postgresql+psycopg://localhost/network_traffic"
    secret_key: str = "dev-secret-change-me"
    access_token_expire_minutes: int = 480
    api_base_url: str = "http://127.0.0.1:8000"

    infobip_base_url: str = ""
    infobip_api_key: str = ""
    infobip_sender: str = ""
    alert_phone_number: str = ""

    agent_mode: str = "sample"
    agent_interval_seconds: float = 5.0
    agent_batch_size: int = 5
    agent_interface: str = "eth0"
    agent_retry_seconds: float = 10.0
    agent_subnet_prefix: str = "192.168.1."


settings = Settings()
