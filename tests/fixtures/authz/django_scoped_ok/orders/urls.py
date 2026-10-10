from django.urls import path

from . import views

urlpatterns = [
    path("orders/<int:pk>/", views.order_detail),
]
