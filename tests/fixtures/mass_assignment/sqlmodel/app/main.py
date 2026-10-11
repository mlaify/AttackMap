# Test fixture (#242): deliberately vulnerable.
from fastapi import FastAPI

from .models import Hero, HeroCreate

app = FastAPI()


@app.post("/heroes")
def create_hero(hero: Hero):
    return hero


@app.post("/heroes/safe")
def create_hero_safe(hero: HeroCreate):
    return Hero.model_validate(hero)


@app.get("/heroes/{hero_id}")
def read_hero(hero_id: int, hero: Hero):
    return hero
