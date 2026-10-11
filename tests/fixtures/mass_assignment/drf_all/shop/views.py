# Test fixture (#242): deliberately vulnerable.
from django.views.generic.edit import UpdateView

from accounts.models import Account


class AccountUpdate(UpdateView):
    model = Account
    fields = "__all__"
