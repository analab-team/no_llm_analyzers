from pydantic_settings import BaseSettings


class DatabaseConfig(BaseSettings):
    clickhouse_host: str
    clickhouse_port: int
    clickhouse_db: str
    clickhouse_user: str
    clickhouse_password: str
