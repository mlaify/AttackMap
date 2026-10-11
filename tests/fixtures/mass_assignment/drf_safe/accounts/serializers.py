# Test fixture (#242): safe binders.
import django_filters
from rest_framework import serializers

from .models import Account, Note


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ["id", "name"]


class AccountAdminSerializer(serializers.ModelSerializer):
    role = serializers.CharField(read_only=True)

    class Meta:
        model = Account
        fields = "__all__"
        read_only_fields = ["is_staff"]


class AccountExcludeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        exclude = ("is_staff",)
        extra_kwargs = {"role": {"read_only": True}}


class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = "__all__"


class AccountFilter(django_filters.FilterSet):
    class Meta:
        model = Account
        fields = "__all__"


class AccountNode(DjangoObjectType):
    class Meta:
        model = Account
        fields = "__all__"


class AccountUpdate(ModelMutation):
    class Arguments:
        input = AccountInput(required=True)

    class Meta:
        model = Account
        exclude = ["password"]
