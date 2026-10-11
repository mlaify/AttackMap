# Test fixture (#242): deliberately vulnerable.
from sqlmodel import Field, SQLModel


class Hero(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str
    is_admin: bool = False


class HeroCreate(SQLModel):
    name: str
