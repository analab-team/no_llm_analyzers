from core.config.models import DatabaseConfig
from dotenv import load_dotenv
from pydantic_settings import BaseSettings


class Config(BaseSettings):
    admin_api_key: str
    
    alerting_endpoint: str

    database: DatabaseConfig


def load_config() -> Config:
    load_dotenv(dotenv_path="/.env", verbose=True)

    database = DatabaseConfig()

    settings = Config(database=database)

    return settings


main_config = load_config()
