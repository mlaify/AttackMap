# Test fixture (#242): safe binders.
from django.db import models


class Account(models.Model):
    name = models.CharField(max_length=100)
    is_staff = models.BooleanField(default=False)
    role = models.CharField(max_length=20)


class Note(models.Model):
    title = models.CharField(max_length=100)
    body = models.TextField()
