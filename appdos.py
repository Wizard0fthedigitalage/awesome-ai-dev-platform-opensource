"""
This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license.
"""
import logging
import uuid
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import generics
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import UserRateThrottle
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth.models import User
from organizations.models import Organization, OrganizationMember
from .models import Invitation
from .serializers import InvitationSerializer

logger = logging.getLogger(__name__)

class InviteThrottle(UserRateThrottle):
    """Custom throttle for invitation endpoint"""
    rate = '5/minute'  # Limit to 5 invites per minute per user

class IsOrgAdmin:
    """Custom permission to allow organization admins to send invites"""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        user = request.user
        if isinstance(obj, Organization):
            if user.is_superuser or user.is_staff:
                return True
            is_org_admin = OrganizationMember.objects.filter(
                organization_id=obj.id,
                user_id=user.id,
                is_admin=True
            ).exists()
            if is_org_admin:
                return True
        logger.warning(
            f"User {user.id} attempted unauthorized access to organization {obj.id} for sending invite"
        )
        return False

class InviteCreateAPI(generics.CreateAPIView):
    """Create an invitation for a new member"""
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated, IsOrgAdmin]
    serializer_class = InvitationSerializer
    throttle_classes = [InviteThrottle]

    def perform_create(self, serializer):
        """Handle invitation creation with email verification before reservation"""
        user = self.request.user
        email = self.request.data.get('email')
        organization_id = self.request.data.get('organizationId')

        # Validate inputs
        if not email:
            logger.warning(f"User {user.id} attempted to create invite without email")
            raise ValidationError("Email is required", code=400)
        if not organization_id:
            logger.warning(f"User {user.id} attempted to create invite without organizationId")
            raise ValidationError("Organization ID is required", code=400)

        try:
            organization = Organization.objects.get(pk=organization_id)
            permission_checker = IsOrgAdmin()
            if not permission_checker.has_object_permission(self.request, self, organization):
                raise PermissionDenied("User lacks organization permissions")
        except Organization.DoesNotExist:
            logger.warning(f"User {user.id} requested non-existent organization {organization_id}")
            raise NotFound("Organization not found")

        # Check if email is already registered or invited
        if User.objects.filter(email=email).exists():
            logger.warning(f"User {user.id} attempted to invite existing user {email}")
            raise ValidationError("User with this email already exists", code=400)
        if Invitation.objects.filter(email=email, is_active=True, is_verified=False).exists():
            logger.warning(f"User {user.id} attempted to invite already invited email {email}")
            raise ValidationError("Email is already invited and awaiting verification", code=400)

        # Generate unique verification token
        verification_token = str(uuid.uuid4())
        invitation = serializer.save(
            email=email,
            organization=organization,
            invited_by=user,
            verification_token=verification_token,
            is_verified=False  # Email not reserved until verified
        )

        # Send verification email
        try:
            verification_url = self.request.build_absolute_uri(
                reverse('verify-invitation', kwargs={'token': verification_token})
            )
            subject = 'ALXBlock Invitation Verification'
            message = (
                f'You have been invited to join ALXBlock for organization ID {organization_id}.\n\n'
                f'Please verify your email by clicking the link below:\n'
                f'{verification_url}\n\n'
                f'This link will expire in 24 hours. If you did not request this invitation, '
                f'you can ignore it or register independently at {self.request.build_absolute_uri("/signup")}.'
            )
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False
            )
            logger.info(f"User {user.id} sent verification email to {email} for organization {organization_id}")
        except Exception as e:
            logger.error(f"Failed to send verification email to {email}: {str(e)}")
            invitation.delete()  # Roll back if email fails
            raise ValidationError("Failed to send verification email", code=500)

    @swagger_auto_schema(
        operation_description="Create an invitation for a new member, requiring email verification before reservation.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email address of the invited user'),
                'organizationId': openapi.Schema(type=openapi.TYPE_INTEGER, description='Organization ID')
            },
            required=['email', 'organizationId']
        ),
        responses={
            201: InvitationSerializer(),
            400: "Invalid input or user already exists",
            403: "Permission Denied",
            404: "Organization not found",
            500: "Failed to send email"
        }
    )
    def post(self, request, *args, **kwargs):
        """Handle POST requests to create an invitation"""
        try:
            return super().post(request, *args, **kwargs)
        except Exception as e:
            logger.error(f"Error creating invitation for user {request.user.id}: {str(e)}")
            raise

class VerifyInvitationAPI(generics.GenericAPIView):
    """Verify an invitation email before reserving it"""
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = []  # No authentication required

    @swagger_auto_schema(
        operation_description="Verify an invitation email using a token, reserving the email.",
        responses={
            200: "Email verified successfully",
            400: "Invalid or expired token",
            500: "Internal server error"
        }
    )
    def get(self, request, token, *args, **kwargs):
        """Handle GET requests for email verification"""
        try:
            invitation = Invitation.objects.get(verification_token=token, is_active=True, is_verified=False)
            if invitation.expires_at < timezone.now():
                logger.warning(f"Expired verification token used: {token}")
                invitation.is_active = False
                invitation.save()
                raise ValidationError("Verification token has expired", code=400)

            # Mark email as verified
            invitation.is_verified = True
            invitation.save()

            logger.info(f"Email {invitation.email} verified for organization {invitation.organization_id}")
            return Response({"message": "Email verified successfully"})
        except Invitation.DoesNotExist:
            logger.warning(f"Invalid verification token used: {token}")
            raise ValidationError("Invalid verification token", code=400)

class RegisterAPI(generics.CreateAPIView):
    """Allow independent registration, overriding unverified invitations"""
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = []  # No authentication required

    @swagger_auto_schema(
        operation_description="Register a new user, overriding unverified invitations for the email.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email address'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password')
            },
            required=['email', 'password']
        ),
        responses={
            201: "User registered successfully",
            400: "Invalid input or email already registered"
        }
    )
    def post(self, request, *args, **kwargs):
        """Handle user registration"""
        email = self.request.data.get('email')
        password = self.request.data.get('password')

        if not email or not password:
            logger.warning(f"Invalid registration attempt: missing email or password")
            raise ValidationError("Email and password are required", code=400)

        # Check if email is already registered
        if User.objects.filter(email=email).exists():
            logger.warning(f"Registration attempt with already registered email {email}")
            raise ValidationError("Email is already registered", code=400)

        # Invalidate unverified invitations for this email
        Invitation.objects.filter(email=email, is_active=True, is_verified=False).update(
            is_active=False,
            expires_at=timezone.now()
        )

        # Create user
        try:
            user = User.objects.create_user(
                username=email,  # Use email as username
                email=email,
                password=password
            )
            logger.info(f"User {user.id} ({user.email}) registered successfully")
            return Response({"message": "User registered successfully"}, status=201)
        except Exception as e:
            logger.error(f"Error registering user with email {email}: {str(e)}")
            raise ValidationError("Failed to register user", code=400)
