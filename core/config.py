from typing import Any, Callable, Set, Annotated
from pprint import pformat
import shutil
from urllib.parse import quote_plus
from datetime import timedelta
from pydantic import (
    # AliasChoices,
    # AmqpDsn,
    # BaseModel,
    StringConstraints,
    Field,
    IPvAnyAddress,
    AnyHttpUrl,
    # ImportString,
    PostgresDsn,
    EmailStr,
    AnyUrl
)

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env',
                                      env_file_encoding='utf-8')

    app_name: str = "Vereinsmanager Main API"

    # postgres_dsn: PostgresDsn = Field(alias="POSTGRES_DSN")
    postgres_username: str
    postgres_password: str
    postgres_host: AnyHttpUrl | IPvAnyAddress
    postgres_database: str

    secret_key: str = Field(alias="VM_SECRET_KEY")
    hash_algorithm: Annotated[str, StringConstraints(pattern="^(HS256)$")] = Field(..., alias="HASH_ALGORITHM")

    superuser_username: str = Field(alias="SUPERUSER_USERNAME")
    superuser_password: str = Field(alias="SUPERUSER_PASSWORD")

    access_token_expire_minutes: str

    jwt_session_lifetime: timedelta = timedelta(minutes=30)

    jwt_refresh_lifetime: timedelta = timedelta(days=7)
    jwt_refresh_token_cookie_name: str = "vm_refresh_token"
    jwt_refresh_token_secure: bool = False

    echo_sql: bool = True

    # email
    smtp_server: str | IPvAnyAddress
    smtp_port: int = 587
    smtp_use_tls: bool = True
    email_address: EmailStr
    email_password: str

    domain: AnyHttpUrl = "http://localhost:8000"

    password_recovery_redirect_url: AnyHttpUrl = "http://localhost:8000/auth/password-recovery"

    # this isnt parsed from env
    @property
    def postgres_dsn(self) -> PostgresDsn:
        password = quote_plus(self.postgres_password)
        return f"postgresql+asyncpg://{self.postgres_username}:{password}@{self.postgres_host}/{self.postgres_database}"  # noqa

    # prevent sensetive cred from being printed
    def model_dump(self, *args, **kwargs):
        d = super().model_dump(*args, **kwargs)
        censored_keys = ["superuser_password",
                         "postgres_password",
                         "secret_key",
                         "email_password"
                         ]
        for key in censored_keys:
            if key in d:
                d[key] = '******'
        return d


settings = Settings()
