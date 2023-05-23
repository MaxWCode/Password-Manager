from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="home"),
    path("vault", views.vault, name="vault"),
    path("account", views.account, name="account"),
    path("login", views.login_view, name="login"),
    path('signup', views.signup, name="signup"),
    path('logout', views.logout_view, name="logout"),
    path('copy_password/<int:password_id>/', views.copy_password, name='copy_password'),
    path("delete_password/<int:password_id>/", views.delete_password, name="delete_password"),
    path("vault_unlock", views.vault_unlock, name="vault_unlock"),
    path('vault_lock', views.vault_lock, name="vault_lock"),
]

