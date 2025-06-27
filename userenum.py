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
from django.contrib.auth.hashers import make_password
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from users.models import User, Organization, OrganizationMember
from users.serializers import UserCompactSerializer, UserRegisterSerializer, ResetPasswordSerializer
from core.utils.common import create_hash
from rest_framework import serializers
from users.functions import send_email_thread
from django.contrib.auth.tokens import PasswordResetTokenGenerator

logger = logging.getLogger(__name__)

class PasswordResetView(generics.ListAPIView):
    serializer_class = ResetPasswordSerializer
    authentication_classes = []
    permission_classes = []
    
    @swagger_auto_schema(
        tags=['Users'],
        operation_summary='Reset Password',
        operation_description='Request a password reset link. Returns a generic response to prevent user enumeration.',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
            },
        ),
        responses={
            200: openapi.Response(description='If the email exists in our system, a password reset link has been sent.'),
            400: openapi.Response(description='Invalid email format'),
        }
    )
    def post(self, request):
        domain_reset = settings.BASE_BACKEND_URL
        if "Origin" in self.request.headers and self.request.headers["Origin"] != domain_reset:
            domain_reset = self.request.headers["Origin"]
        email = self.request.data.get("email", "").strip().lower()

        if not email:
            return Response({'detail': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if user exists, but don't reveal in response
        user = User.objects.filter(email=email).first()
        if user:
            token_generator = PasswordResetTokenGenerator()
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = token_generator._make_token_with_timestamp(user, int((datetime.now() + timedelta(minutes=60*24)).timestamp()))
            reset_link = f'{domain_reset}/user/reset-password/?uidb64={uidb64}&token={token}'
            reset_link = re.sub(r'(?<!:)//+', '/', reset_link)
            send_to = user.username if user.username else user.email
            html_file_path = './aixblock_labeltool/templates/mail/reset-password.html'

            with open(html_file_path, 'r', encoding='utf-8') as file:
                html_content = file.read()
            html_content = html_content.replace('[user]', f'{send_to}')
            html_content = html_content.replace('[Link_reset]', reset_link)

            data = {
                "subject": "Reset Your Password AIxBlock",
                "from": "noreply@aixblock.io",
                "to": [f"{user.email}"],
                "html": html_content,
                "text": 'Reset password',
            }
            docket_api = "tcp://69.197.168.145:4243"
            host_name = settings.MAIL_SERVER

            email_thread = threading.Thread(target=send_email_thread, args=(docket_api, host_name, data,))
            email_thread.start()
            logger.info(f"Password reset email sent for user: {email}")

        # Always return generic response
        return Response(
            {'detail': 'If the email exists in our system, a password reset link has been sent.'},
            status=status.HTTP_200_OK
        )

# Other classes (UserRegisterApi, LoginAPI, etc.) remain unchanged
# Omitted for brevity, as they are not relevant to the user enumeration fix

