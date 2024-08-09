from rest_framework import serializers
from .models import Author, Post
from django.contrib.auth.models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password']

class AuthorSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = Author
        fields = ['id', 'user', 'name', 'email', 'bio']

class PostSerializer(serializers.ModelSerializer):
    author = serializers.ReadOnlyField(source='author.user.username')

    class Meta:
        model = Post
        fields = ['id', 'title', 'content', 'created_at', 'location_lat', 'location_long', 'author']
        read_only_fields = ['author', 'location_lang', 'location_long']
