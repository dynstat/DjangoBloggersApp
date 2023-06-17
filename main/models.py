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
    email_verification = models.BooleanField(default=0)
    is_expired = models.BooleanField(default=False)


class Blog(models.Model):
    rel_user = models.ForeignKey(User, on_delete=models.CASCADE, null=False)
    title = models.TextField()
    content = models.TextField()
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now_add=True)
    published_url = models.URLField(max_length=100, default="")
    publish_active = models.BooleanField(default=False)


class Published(models.Model):
    id = models.AutoField(default=1, primary_key=True)
    uid = models.CharField(max_length=100)
    rel_blog = models.ForeignKey(Blog, null=False, on_delete=models.CASCADE)


class DemoUrl(models.Model):
    demo_uid = models.CharField(max_length=100, default="")
    rel_blog = models.ForeignKey(Blog, null=False, on_delete=models.CASCADE)
