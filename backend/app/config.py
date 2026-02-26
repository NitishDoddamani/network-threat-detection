from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/threatdetection"
    REDIS_URL: str = "redis://localhost:6379"
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_TOPIC: str = "network-threats"

    class Config:
        env_file = ".env"

settings = Settings()
