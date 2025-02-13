from django.urls import path
from . import views
from two_factor.urls import urlpatterns as tf_urls
from django.urls import include

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path("account/", include(tf_urls)),
]
