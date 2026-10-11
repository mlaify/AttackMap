# Test fixture (#242): deliberately vulnerable.
from django import forms
from django.contrib.auth.models import User


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = "__all__"
