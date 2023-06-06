from django.db import models
from django.utils import timezone
# Create your models here.


class User(models.Model):
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    email = models.EmailField()
    session_id = models.CharField(max_length=100, default=0)
    time_stamp = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(default=timezone.now)
    is_expired = models.BooleanField(default=False)
    email_verification = models.BooleanField(default=0)

class Blog(models.Model):
    rel_user = models.ForeignKey(User, on_delete=models.CASCADE, null=False)
    title = models.TextField()
    content= models.TextField()
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now_add=True)
