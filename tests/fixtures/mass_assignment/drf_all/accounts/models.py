# Test fixture (#242): deliberately vulnerable.
from django.contrib.auth.models import AbstractUser
from django.db import models


class Account(models.Model):
    name = models.CharField(max_length=100)
    is_staff = models.BooleanField(default=False)
    balance = models.DecimalField(max_digits=12, decimal_places=2)


class Member(AbstractUser):
    bio = models.TextField(blank=True)
