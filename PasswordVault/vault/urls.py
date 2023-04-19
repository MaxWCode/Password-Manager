from django.urls import path

from . import views

urlpatterns = [
    path("home", views.index, name="home"),
    path("vault", views.vault, name="vault"),
    path("login", views.login_view, name="login"),
    path('signup', views.signup, name="signup"),
    path('logout', views.logout_view, name="logout"),
]
