from django.db import models
from django.contrib.auth.models import User

class Author(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    bio = models.TextField(blank=True)

    def __str__(self):
        return self.name

class Post(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    location_lat = models.FloatField(blank=True, null=True)
    location_long = models.FloatField(blank=True, null=True)
    author = models.ForeignKey(Author, on_delete=models.CASCADE, related_name='posts')

    def __str__(self):
        return self.title 
