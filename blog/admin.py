from django.contrib import admin
from .models import Author, Post

class AuthorAdmin(admin.ModelAdmin):
    list_display = ('user', 'name', 'email', 'bio')
    search_fields = ('user__username', 'user__email')

class PostAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'created_at', 'location_lat', 'location_long')
    search_fields = ('title', 'author__user__username', 'content')
    list_filter = ('created_at',)

admin.site.register(Author, AuthorAdmin)
admin.site.register(Post, PostAdmin)

