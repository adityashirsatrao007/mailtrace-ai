from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "MailTrace AI"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    ML_MODEL_PATH: str = "app/ml/models"
    MAX_EMAIL_SIZE_KB: int = 500
    GEOIP_DB_PATH: str = "app/services/GeoLite2-City.mmdb"

    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER: str = "redis://localhost:6379/1"

    GEOLOCATION_API: str = "http://ip-api.com/json/{ip}"
    WHOIS_ENABLED: bool = True

    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    class Config:
        env_file = ".env"


settings = Settings()
