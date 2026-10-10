# #242: the view scopes the lookup to the caller (user=request.user), one hop
# from the URLconf that declares the route.
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404

from .models import Order


@login_required
def order_detail(request, pk):
    order = get_object_or_404(Order, pk=pk, user=request.user)
    return JsonResponse({"id": order.pk, "total": order.total})
