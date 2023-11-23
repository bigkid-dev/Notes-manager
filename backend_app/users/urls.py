from django.urls import path
from .serializers import *
from .views import *


urlpatterns = [
    path("signup/", UserSignUpAPIView.as_view(), name="signup"),
    path("signin/", UserSignInAPIView.as_view(), name="signin"),
    path("me/", UserDetailsAPIView.as_view(), name="user_details"),


    
]
