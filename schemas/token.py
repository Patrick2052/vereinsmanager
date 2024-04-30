from pydantic import BaseModel


class TokenPayload(BaseModel):
    sub: str | None = None
    # user_id: str
    exp: int
    type: str
