from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Info(models.Model):
    website_name = models.CharField(max_length=50)
    username = models.CharField(max_length=50)
    website_password = models.CharField(max_length=50)
    user_account = models.ForeignKey(User, on_delete=models.CASCADE, related_name="passwords")

    def __str__(self):
        return f"{self.website_name} ('{self.username} : {self.website_password}') -- ({self.user_account})"
