"""This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license."""
import json
import logging
import urllib.parse
import re
from datetime import datetime, timedelta
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect, HttpResponseNotFound, HttpResponse
from django.db.models import Q
from django.contrib.auth import authenticate, login
from django.utils import timezone
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from users.models import User, Organization, OrganizationMember
from users.serializers import UserCompactSerializer, UserRegisterSerializer
from core.utils.common import create_hash
from rest_framework import serializers

logger = logging.getLogger(__name__)

# Configuration for rate limiting and lockout
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_LOCKOUT_MINUTES = 5
CAPTCHA_THRESHOLD = 3

# Password validation configuration
MIN_PASSWORD_LENGTH = 8
COMMON_PASSWORDS = ['123456', 'password', 'admin123', 'qwerty', 'abc123']

def validate_password_strength(password):
    """Custom password validator for strong passwords."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if not re.search(r'[A-Z]', password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        raise ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r'[0-9]', password):
        raise ValidationError("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError("Password must contain at least one special character.")
    if password.lower() in COMMON_PASSWORDS:
        raise ValidationError("Password is too common.")
    return password

class UserRegisterSerializer(serializers.ModelSerializer):
    role = serializers.ChoiceField(choices=[(r, r) for r in ['compute_supplier', 'model_seller', 'labeler']])
    
    class Meta:
        model = User
        fields = ['email', 'password', 'role']
    
    def validate_password(self, value):
        """Validate password strength during registration."""
        validate_password_strength(value)
        return value

class LoginAPI(APIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    permission_classes = (AllowAny,)
    
    @swagger_auto_schema(
        tags=['Users'],
        operation_summary='User Login',
        operation_description='Authenticate a user with email and password, with user-based and IP-based rate limiting.',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'password'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
                'captcha_token': openapi.Schema(type=openapi.TYPE_STRING, description='CAPTCHA token (required after 3 failed attempts)', nullable=True),
            },
        ),
        responses={
            200: openapi.Response(description='Login successful', schema=UserCompactSerializer),
            400: openapi.Response(description='Invalid credentials or missing CAPTCHA'),
            429: openapi.Response(description='Too many login attempts'),
            423: openapi.Response(description='Account locked'),
        }
    )
    def post(self, request, *args, **kwargs):
        email = request.data.get('email', '').strip().lower()
        password = request.data.get('password', '')
        captcha_token = request.data.get('captcha_token', None)
        client_ip = self._get_client_ip(request)

        if not email or not password:
            return Response(
                {"error": "Email and password are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check user-based rate limiting
        user_key = f"login_attempts_user_{email}"
        ip_key = f"login_attempts_ip_{client_ip}"
        user_attempts = cache.get(user_key, 0)
        ip_attempts = cache.get(ip_key, 0)
        
        # Check if account is locked
        lockout_key = f"login_lockout_{email}"
        if cache.get(lockout_key):
            return Response(
                {
                    "status": 423,
                    "error": f"Account locked due to too many failed attempts. Try again in {LOGIN_LOCKOUT_MINUTES} minutes."
                },
                status=status.HTTP_423_LOCKED
            )

        # Require CAPTCHA after 3 failed attempts
        if userInstances[0]: user_attempts >= CAPTCHA_THRESHOLD:
            if not captcha_token or not self._verify_captcha(captcha_token):
                return Response(
                    {"error": "CAPTCHA required and must be valid"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Check rate limits
        if user_attempts >= LOGIN_ATTEMPT_LIMIT or ip_attempts >= LOGIN_ATTEMPT_LIMIT:
            # Lock account for user-based attempts
            if user_attempts >= LOGIN_ATTEMPT_LIMIT:
                cache.set(lockout_key, True, LOGIN_LOCKOUT_MINUTES * 60)
                logger.warning(f"Account locked for email: {email}, IP: {client_ip}")
            return Response(
                {
                    "status": 429,
                    "error": f"You have exceeded the maximum number of {LOGIN_ATTEMPT_LIMIT} login attempts. Please try again in {LOGIN_LOCKOUT_MINUTES} minutes."
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        # Authenticate user
        user = authenticate(request, username=email, password=password)
        if user is None:
            # Increment attempt counters
            cache.incr(user_key, 1) if cache.get(user_key) else cache.set(user_key, 1, 3600)
            cache.incr(ip_key, 1) if cache.get(ip_key) else cache.set(ip_key, 1, 3600)
            logger.info(f"Failed login attempt for email: {email}, IP: {client_ip}, User attempts: {user_attempts + 1}, IP attempts: {ip_attempts + 1}")
            return Response(
                {
                    "status": 400,
                    "errors": {"all": ["The email and password you entered don't match."]}
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # Successful login
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        cache.delete(user_key)  # Reset user attempts on success
        cache.delete(ip_key)    # Reset IP attempts on success
        logger.info(f"Successful login for email: {email}, IP: {client_ip}")

        # Return minimal user data
        serializer = UserCompactSerializer(user)
        return Response(
            {
                "message": "Login successful",
                "data": serializer.data
            },
            status=status.HTTP_200_OK
        )

    def _get_client_ip(self, request):
        """Extract client IP from request headers."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR', 'unknown')

    def _verify_captcha(self, captcha_token):
        """Verify CAPTCHA token (e.g., Google reCAPTCHA)."""
        # Placeholder: Implement actual CAPTCHA verification (e.g., Google reCAPTCHA API)
        # Example: Send captcha_token to reCAPTCHA API and check response
        return bool(captcha_token)  # Replace with actual verification logic

class UserRegisterApi(generics.CreateAPIView):
    authentication_classes = []
    permission_classes = []
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer

    @swagger_auto_schema(
        tags=['Users'],
        operation_summary='SignUp An User',
        operation_description='Create a new user with strong password validation.',
        request_body=UserRegisterSerializer,
        responses={
            201: openapi.Response(description='Register successful'),
            400: openapi.Response(description='Invalid email, password, or role'),
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = UserRegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email'].strip().lower()
        password = serializer.validated_data['password']
        role = serializer.validated_data['role']

        # Check if email is taken
        if User.objects.filter(email=email).exists():
            return Response({'error': 'Your email is taken'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate email (using existing logic)
        email_validate = is_valid_email(email)
        email_verified = False
        if not email_validate['has_error'] and email_validate['is_valid']:
            email_verified = True
        elif email_validate['has_error']:
            return Response({'error': 'Your email address is not valid'}, status=status.HTTP_400_BAD_REQUEST)

        # Create user with hashed password
        user = User.objects.create(
            email=email,
            username=email,
            password=make_password(password),
            is_verified=email_verified,
        )
        if role == 'compute_supplier':
            user.is_compute_supplier = True
        elif role == 'model_seller':
            user.is_model_seller = True
        elif role == 'labeler':
            user.is_labeler = True
        user.save()

        # Create organization
        token = create_hash()
        team_id = create_hash()
        organization = Organization.objects.create(
            title=email,
            created_by=user,
            token=token,
            team_id=team_id,
            status="actived"
        )
        OrganizationMember.objects.create(organization=organization, user=user, is_admin=True)

        # Send registration email
        html_file_path = './aixblock_labeltool/templates/mail/register.html'
        with open(html_file_path, 'r', encoding='utf-8') as file:
            html_content = file.read()
        send_to = user.username if user.username else user.email
        html_content = html_content.replace('[user]', f'{send_to}')
        data = {
            "subject": "Welcome to AIxBlock - Registration Successful!",
            "from": "noreply@aixblock.io",
            "to": [f"{user.email}"],
            "html": html_content,
        }
        docket_api = "tcp://69.197.168.145:4243"
        host_name = settings.MAIL_SERVER
        _send_mail = True
        if "Host" in self.request.headers:
            if "app.aixblock.io" not in self.request.headers["Host"] and "stag.aixblock.io" not in self.request.headers["Host"]:
                _send_mail = False
        if _send_mail:
            email_thread = threading.Thread(target=send_email_thread, args=(docket_api, host_name, data,))
            email_thread.start()

        # Assign active organization and reward points
        user.active_organization = organization
        user.save()
        if settings.REGISTER_TOPUP > 0:
            reward_point_register(user, topup_amount=settings.REGISTER_TOPUP)

        # Log in the new user
        auth.login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        logger.info(f"User registered and logged in: {email}")
        return Response({'message': 'Register successful'}, status=status.HTTP_201_CREATED)

# Existing classes from original tasks.py (omitted for brevity, assumed unchanged)
# Include UserWhoAmIAPI, UserAPI, etc., as needed

