from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="home"),
    path("vault", views.vault, name="vault"),
    path("login", views.login_view, name="login"),
    path('signup', views.signup, name="signup"),
    path('logout', views.logout_view, name="logout"),
    path('copy_password/<int:password_id>/', views.copy_password, name='copy_password')
]

