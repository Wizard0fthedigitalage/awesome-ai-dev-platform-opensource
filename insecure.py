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
from rest_framework.parsers import JSONParser, MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import UserRateThrottle
from drf_yasg.utils import swagger_auto_schema
from django.contrib.auth.models import User
from projects.models import Project
from organizations.models import Organization, OrganizationMember
from .models import Invitation
from .serializers import InvitationSerializer
from .utils import get_object_with_check_and_log

logger = logging.getLogger(__name__)

class InviteThrottle(UserRateThrottle):
    """Custom throttle for /api/invite/csv endpoint"""
    rate = '5/minute'  # Limit to 5 invites per minute per user

class IsProjectOwnerOrOrgAdmin:
    """Custom permission to allow project owners or organization admins to send invites"""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        user = request.user
        if isinstance(obj, Project):
            # Allow project owner or organization admin
            if obj.created_by_id == user.id or user.is_superuser or user.is_staff:
                return True
            is_org_admin = OrganizationMember.objects.filter(
                organization_id=obj.organization_id,
                user_id=user.id,
                is_admin=True
            ).exists()
            if is_org_admin:
                return True
        elif isinstance(obj, Organization):
            # Allow organization admin
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
            f"User {user.id} attempted unauthorized access to {type(obj).__name__} {obj.id} for sending invite"
        )
        return False

class InviteCSVCreateAPI(generics.CreateAPIView):
    """Create an invitation for a new member via CSV endpoint"""
    parser_classes = (JSONParser, MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated, IsProjectOwnerOrOrgAdmin]
    serializer_class = InvitationSerializer
    throttle_classes = [InviteThrottle]

    def perform_create(self, serializer):
        """Handle invitation creation with secure token and email"""
        user = self.request.user
        email = self.request.data.get('email')
        username = self.request.data.get('username')
        role = self.request.data.get('role', 'member')  # Default to 'member'
        organization_id = self.request.data.get('organizationId')
        project_id = self.request.data.get('project_id')

        # Validate inputs
        if not email:
            logger.warning(f"User {user.id} attempted to create invite without email")
            raise ValidationError("Email is required", code=400)
        if not organization_id:
            logger.warning(f"User {user.id} attempted to create invite without organizationId")
            raise ValidationError("Organization ID is required", code=400)

        try:
            organization = get_object_with_check_and_log(self.request, Organization, pk=organization_id)
        except Organization.DoesNotExist:
            logger.warning(f"User {user.id} requested non-existent organization {organization_id}")
            raise NotFound("Organization not found")

        project = None
        if project_id:
            try:
                project = get_object_with_check_and_log(self.request, Project, pk=project_id)
                if project.organization_id != int(organization_id):
                    logger.warning(f"User {user.id} provided mismatched project {project_id} for organization {organization_id}")
                    raise ValidationError("Project does not belong to the specified organization", code=400)
            except Project.DoesNotExist:
                logger.warning(f"User {user.id} requested non-existent project {project_id}")
                raise NotFound("Project not found")

        # Validate role
        valid_roles = ['member', 'admin']
        if role not in valid_roles:
            logger.warning(f"User {user.id} provided invalid role {role} for invite to {email}")
            raise ValidationError(f"Invalid role. Must be one of: {', '.join(valid_roles)}", code=400)

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            logger.warning(f"User {user.id} attempted to invite existing user {email}")
            raise ValidationError("User with this email already exists", code=400)

        # Generate unique invitation token
        token = str(uuid.uuid4())
        invitation = serializer.save(
            email=email,
            username=username,
            project=project,
            organization=organization,
            invited_by=user,
            token=token,
            role=role
        )

        # Send secure invitation email
        try:
            activation_url = self.request.build_absolute_uri(
                reverse('activate-account', kwargs={'token': token})
            )
            subject = 'ALXBlock Invitation'
            message = (
                f'You have been invited to join ALXBlock as a {role} for organization ID {organization_id}.\n\n'
                f'Click the link below to activate your account and set your password:\n'
                f'{activation_url}\n\n'
                f'This link will expire in 24 hours.'
            )
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False
            )
            logger.info(f"User {user.id} sent invitation to {email} for organization {organization_id}")
        except Exception as e:
            logger.error(f"Failed to send invitation email to {email}: {str(e)}")
            invitation.delete()  # Roll back if email fails
            raise ValidationError("Failed to send invitation email", code=500)

    @swagger_auto_schema(
        operation_description="Create an invitation for a new member via CSV upload, sending a tokenized activation link.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description='Username for the invited user'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email address of the invited user'),
                'role': openapi.Schema(type=openapi.TYPE_STRING, description='Role (member or admin)'),
                'organizationId': openapi.Schema(type=openapi.TYPE_INTEGER, description='Organization ID'),
                'project_id': openapi.Schema(type=openapi.TYPE_STRING, description='Project ID (optional)')
            },
            required=['email', 'organizationId']
        ),
        responses={
            201: InvitationSerializer(),
            400: "Invalid input or user already exists",
            403: "Permission Denied",
            404: "Organization or project not found",
            500: "Failed to send email"
        }
    )
    def post(self, request, *args, **kwargs):
        """Handle POST requests to /api/invite/csv"""
        try:
            return super().post(request, *args, **kwargs)
        except Exception as e:
            logger.error(f"Error creating invitation for user {request.user.id}: {str(e)}")
            raise

class AccountActivationAPI(generics.GenericAPIView):
    """Activate an account using an invitation token"""
    parser_classes = (JSONParser, MultiPartParser, FormParser)
    permission_classes = []  # No authentication required for activation

    @swagger_auto_schema(
        operation_description="Activate a user account using an invitation token and set a password.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'token': openapi.Schema(type=openapi.TYPE_STRING, description='Invitation token'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='New password')
            },
            required=['token', 'password']
        ),
        responses={
            200: "Account activated successfully",
            400: "Invalid or expired token",
            500: "Internal server error"
        }
    )
    def post(self, request, *args, **kwargs):
        """Handle account activation"""
        token = request.data.get('token')
        password = request.data.get('password')

        if not token or not password:
            logger.warning(f"Invalid activation attempt: missing token or password")
            raise ValidationError("Token and password are required", code=400)

        try:
            invitation = Invitation.objects.get(token=token, is_active=True)
            if invitation.expires_at < timezone.now():
                logger.warning(f"Expired token used for activation: {token}")
                invitation.is_active = False
                invitation.save()
                raise ValidationError("Invitation token has expired", code=400)

            # Create user account
            username = invitation.username or invitation.email  # Use provided username or email
            user = User.objects.create_user(
                username=username,
                email=invitation.email,
                password=password  # Password is hashed automatically by create_user
            )

            # Create organization membership
            OrganizationMember.objects.create(
                organization=invitation.organization,
                user=user,
                is_admin=(invitation.role == 'admin')
            )

            # Mark invitation as used
            invitation.is_active = False
            invitation.accepted_at = timezone.now()
            invitation.accepted_by = user
            invitation.save()

            logger.info(f"User {user.id} ({user.email}) activated account via token {token}")
            return Response({"message": "Account activated successfully"})
        except Invitation.DoesNotExist:
            logger.warning(f"Invalid token used for activation: {token}")
            raise ValidationError("Invalid invitation token", code=400)
        except Exception as e:
            logger.error(f"Error activating account with token {token}: {str(e)}")
            raise

