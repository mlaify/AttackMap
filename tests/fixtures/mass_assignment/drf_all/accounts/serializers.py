# Test fixture (#242): deliberately vulnerable.
from rest_framework import serializers

from .models import Account, Member


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = "__all__"


class MemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Member
        exclude = ["password"]
