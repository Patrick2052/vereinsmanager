from pydantic import BaseModel


class TokenPayload(BaseModel):
    sub: int | None = None