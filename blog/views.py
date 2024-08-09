from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAuthenticatedOrReadOnly
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken , AccessToken
from rest_framework_simplejwt.views import TokenObtainPairView

import requests
import logging
from django.urls import reverse
from rest_framework.request import Request

from .models import Author, Post
from .serializers import AuthorSerializer, PostSerializer

logger = logging.getLogger(__name__)

class AuthorViewSet(viewsets.ModelViewSet):
    queryset = Author.objects.all()
    serializer_class = AuthorSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]

    def get_permissions(self):
        if self.action in ['create', 'list', 'retrieve']:
            return [AllowAny()]
        return [IsAuthenticated()]

    def create(self, request: Request, *args, **kwargs):
        name = request.data.get('name')
        email = request.data.get('email')
        bio = request.data.get('bio', '')
        password = request.data.get('password')
        username = request.data.get('username')
        
        if not name or not email or not password:
            return Response({'error': 'Please provide name, email, and password'}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(email=email).exists():
            return Response({'error': 'An author with this email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.create_user(username=username, password=password)
        author = Author.objects.create(user=user, bio=bio, email=email, name=name)
        
        login_url = request.build_absolute_uri(reverse('token_obtain_pair'))
        
        return Response({
            'author_id': author.id,
            'name': author.name,
            'email': author.email,
            'login_url': login_url
        }, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        # Check if the user is the author or an admin
        if instance.user != request.user and not request.user.is_staff:
            return Response({
                'error': "You cannot edit this author profile."
            }, status=status.HTTP_403_FORBIDDEN)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.user != request.user and not request.user.is_staff:
            return Response({
                'error': "You cannot delete this author profile."
            }, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)

class LoginView(TokenObtainPairView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class PostViewSet(viewsets.ModelViewSet):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [AllowAny()]
        return [IsAuthenticated()]

    def perform_create(self, serializer):
        author = self.request.user.author
        location = self.request.data.get('location', '')

        api_keys = 'arVeynf2smwctTjEPzvMNBpAYWtXbHzNr6LvMaGK'

        if location:
            try:
                ola_api_url = f"https://api.olamaps.io/places/v1/autocomplete?input={location}&api_key={api_keys}"
                response = requests.get(ola_api_url)
                response.raise_for_status()
                data = response.json()
                
                first_result = data.get('predictions', [])[0]
                latitude = first_result.get('geometry', {}).get('location', {}).get('lat')
                longitude = first_result.get('geometry', {}).get('location', {}).get('lng')
                
                if latitude and longitude:
                    serializer.save(author=author, location_lat=latitude, location_long=longitude)
                else:
                    logger.warning(f"No coordinates found for location: {location}")
                    serializer.save(author=author)
            except requests.RequestException as e:
                logger.error(f"Error fetching location data: {str(e)}")
                serializer.save(author=author)
            except (KeyError, IndexError) as e:
                logger.error(f"Error parsing location data: {str(e)}")
                serializer.save(author=author)
        else:
            serializer.save(author=author)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.author != request.user.author:
            return Response({
                'error': f"You cannot edit this post. This is {instance.author.name}'s post."
            }, status=status.HTTP_403_FORBIDDEN)

        # Fetch and update location data during update
        location = request.data.get('location', '')

        api_keys = 'arVeynf2smwctTjEPzvMNBpAYWtXbHzNr6LvMaGK'

        if location:
            try:
                ola_api_url = f"https://api.olamaps.io/places/v1/autocomplete?input={location}&api_key={api_keys}"
                response = requests.get(ola_api_url)
                response.raise_for_status()
                data = response.json()
                
                first_result = data.get('predictions', [])[0]
                latitude = first_result.get('geometry', {}).get('location', {}).get('lat')
                longitude = first_result.get('geometry', {}).get('location', {}).get('lng')
                
                if latitude and longitude:
                    instance.location_lat = latitude
                    instance.location_long = longitude
                else:
                    logger.warning(f"No coordinates found for location: {location}")

            except requests.RequestException as e:
                logger.error(f"Error fetching location data: {str(e)}")
            except (KeyError, IndexError) as e:
                logger.error(f"Error parsing location data: {str(e)}")

        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.author != request.user.author:
            return Response({
                'error': f"You cannot delete this post. This is {instance.author.name}'s post."
            }, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)
