from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AuthorViewSet, PostViewSet, LoginView, LogoutView

router = DefaultRouter()
router.register(r'authors', AuthorViewSet)
router.register(r'posts', PostViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('login/', LoginView.as_view(), name='token_obtain_pair'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
