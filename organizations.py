"""
This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license.
"""

import copy
import csv
import json
import logging
import os
import re
import time
import threading
from datetime import datetime
import random
import drf_yasg.openapi as openapi

from django.http import HttpResponse, Http404
from django.urls import reverse
from django.conf import settings
from rest_framework.parsers import (
    FormParser,
    JSONParser,
    MultiPartParser,
    FileUploadParser,
)
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework.exceptions import ValidationError, PermissionDenied

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from core.utils.common import create_hash
from django.utils.decorators import method_decorator

from aixblock_core.core.permissions import all_permissions, ViewClassPermission, permission_org
from aixblock_core.core.utils.common import get_object_with_check_and_log
from aixblock_core.projects.serializers import GetFieldsSerializer, ProjectSerializer

from organizations.models import Organization, OrganizationMember, Organization_Project_Permission
from organizations.serializers import (
    OrganizationReporRequest,
    OrganizationSerializer,
    OrganizationIdSerializer,
    OrganizationMemberUserSerializer,
    OrganizationInviteSerializer,
    OrganizationsParamsSerializer, OrganizationMemberSerializer,
)
from core.feature_flags import flag_set
from projects.models import Project
from tasks.models import Task
from rest_framework.permissions import IsAuthenticated, AllowAny
from users.models import User
from core.utils.paginate import SetPagination
from users.serializers import UserAdminViewSerializer
from users.service_notify import send_email_thread
from core.settings.base import MAIL_SERVER

logger = logging.getLogger(__name__)
HOSTNAME = os.environ.get("HOST", "https://app.aixblock.io")


@method_decorator(
    name="get",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="List your organizations",
        operation_description="""
        Return a list of the organizations you've created or that you have access to.
        """,
    ),
)
class OrganizationListAPI(generics.ListCreateAPIView):
    queryset = Organization.objects.all()
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    permission_required = ViewClassPermission(
        GET=all_permissions.organizations_view,
        PUT=all_permissions.organizations_change,
        POST=all_permissions.organizations_create,
        PATCH=all_permissions.organizations_change,
        DELETE=all_permissions.organizations_change,
    )
    serializer_class = OrganizationIdSerializer

    def get_object(self):
        # Fixed IDOR vulnerability (#47): Ensure user is a member of the organization
        org = get_object_with_check_and_log(
            self.request, Organization, pk=self.kwargs[self.lookup_field]
        )
        # Check if user is a member of the organization or a superuser
        if not OrganizationMember.objects.filter(user=self.request.user, organization=org).exists() and not self.request.user.is_superuser:
            logger.warning(f"User {self.request.user.id} attempted to access organization {org.id} without membership")
            raise PermissionDenied("You are not a member of this organization")
        self.check_object_permissions(self.request, org)
        return org

    def filter_queryset(self, queryset):
        # Existing filter ensures only organizations the user is a member of are returned
        organization_ids = OrganizationMember.objects.filter(user_id=self.request.user.id).values_list("organization_id", flat=True)
        return queryset.filter(id__in=organization_ids)

    def get(self, request, *args, **kwargs):
        return super(OrganizationListAPI, self).get(request, *args, **kwargs)

    @swagger_auto_schema(auto_schema=None)
    def post(self, request, *args, **kwargs):
        # Fixed IDOR vulnerability (#47): Ensure user has permission to create organizations
        if not self.request.user.has_perm(all_permissions.organizations_create) and not self.request.user.is_superuser:
            logger.warning(f"User {self.request.user.id} attempted to create an organization without permission")
            raise PermissionDenied("You do not have permission to create an organization")
        return super(OrganizationListAPI, self).post(request, *args, **kwargs)


class OrganizationMemberPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"

    def get_page_size(self, request):
        # emulate "unlimited" page_size
        if (
            self.page_size_query_param in request.query_params
            and request.query_params[self.page_size_query_param] == "-1"
        ):
            return 1000000
        return super().get_page_size(request)


@method_decorator(
    name="get",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Get organization members list",
        operation_description="Retrieve a list of the organization members and their IDs.",
        manual_parameters=[
            openapi.Parameter(
                name="id",
                type=openapi.TYPE_INTEGER,
                in_=openapi.IN_PATH,
                description="A unique integer value identifying this organization.",
            ),
            openapi.Parameter(name="project_id", in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER, required=False),
            openapi.Parameter(name="search", in_=openapi.IN_QUERY, type=openapi.TYPE_STRING),
        ],
    ),
)
class OrganizationMemberListAPI(generics.ListAPIView, generics.UpdateAPIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    permission_required = ViewClassPermission(
        GET=all_permissions.organizations_view,
        PUT=all_permissions.organizations_change,
        PATCH=all_permissions.organizations_change,
        DELETE=all_permissions.organizations_change,
    )
    serializer_class = OrganizationMemberUserSerializer
    pagination_class = OrganizationMemberPagination

    def get_serializer_context(self):
        return {
            "contributed_to_projects": bool_from_request(
                self.request.GET, "contributed_to_projects", False
            ),
            "request": self.request,
        }

    def get_queryset(self):
        try:
            org = Organization.objects.filter(pk=self.kwargs[self.lookup_field]).first()
        except Http404:
            return OrganizationMember.objects.filter(user_id=0)

        # Already fixed for IDOR (#47): Verify organization membership
        if not OrganizationMember.objects.filter(user=self.request.user, organization=org).exists() and not self.request.user.is_superuser:
            raise PermissionDenied("You are not a member of this organization")

        if flag_set(
            "fix_backend_dev_3134_exclude_deactivated_users", self.request.user
        ):
            project_id = self.request.query_params.get("project_id")
            
            serializer = OrganizationsParamsSerializer(data=self.request.GET)
            serializer.is_valid(raise_exception=True)
            active = serializer.validated_data.get("active")

            # return only active users (exclude DISABLED and NOT_ACTIVATED)
            if active:
                return org.active_members.order_by("user__username")
            
            from django.db.models import Q
            
            if project_id:
                org_member_id = Organization_Project_Permission.objects.filter(organization=org, project_id_id=int(project_id)).values_list("user_id", flat=True)
                org_filter = org.members.filter(
                    Q(level_org=False, user_id__in=org_member_id) | Q(level_org=True)
                )

                for member in org_filter:
                    project_permission = Organization_Project_Permission.objects.filter(
                        organization=org, project_id_id=int(project_id), user_id=member.user_id
                    ).first()
                    
                    if project_permission:
                        member.user.is_qa = project_permission.is_qa
                        member.user.is_qc = project_permission.is_qc
            else:
                org_filter = org.members

            # organization page to show all members
            queryset = org_filter
        else:
            queryset = org.members

        search = self.request.query_params.get('search', None)

        if search:
            queryset = queryset.filter(
                Q(user__username__icontains=search)
                | Q(user__email__icontains=search)
                | Q(user__first_name__icontains=search)
                | Q(user__last_name__icontains=search)
            )

        return queryset


@method_decorator(
    name="patch",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Update organization membership",
    ),
)
@method_decorator(
    name="put",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Update organization membership",
    ),
)
class OrganizationMembershipAPI(generics.UpdateAPIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    permission_required = ViewClassPermission(
        PUT=all_permissions.organizations_change,
        PATCH=all_permissions.organizations_change,
    )
    serializer_class = OrganizationMemberSerializer
    queryset = OrganizationMember.objects.all()


@method_decorator(
    name="get",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Get organization settings",
        operation_description="Retrieve the settings for a specific organization by ID.",
    ),
)
@method_decorator(
    name="patch",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Update organization settings",
        operation_description="Update the settings for a specific organization by ID.",
    ),
)
class OrganizationAPI(generics.RetrieveUpdateAPIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    queryset = Organization.objects.all()
    permission_required = all_permissions.organizations_change
    serializer_class = OrganizationSerializer
    redirect_route = "organizations-dashboard"
    redirect_kwarg = "pk"

    def get_object(self):
        org = Organization.objects.filter(pk=self.kwargs[self.lookup_field]).first()
        self.check_object_permissions(self.request, org)
        return org

    def get(self, request, *args, **kwargs):
        return super(OrganizationAPI, self).get(request, *args, **kwargs)

    def patch(self, request, *args, **kwargs):
        return super(OrganizationAPI, self).patch(request, *args, **kwargs)

    @swagger_auto_schema(auto_schema=None)
    def put(self, request, *args, **kwargs):
        return super(OrganizationAPI, self).put(request, *args, **kwargs)


@method_decorator(
    name="patch",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Update organization settings",
        operation_description="Update the settings for a specific organization by ID.",
        request_body=OrganizationSerializer,
    ),
)
class OrganizationPatchAPI(generics.UpdateAPIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    queryset = Organization.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = OrganizationSerializer

    redirect_route = "organizations-dashboard"
    redirect_kwarg = "pk"

    def patch(self, request, *args, **kwargs):
        return super(OrganizationPatchAPI, self).patch(request, *args, **kwargs)

    @swagger_auto_schema(auto_schema=None)
    def put(self, request, *args, **kwargs):
        return super(OrganizationPatchAPI, self).put(request, *args, **kwargs)


@method_decorator(
    name="delete",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Delete organization",
        operation_description="Delete organization by ID.",
    ),
)
class OrganizationDeleteAPI(generics.DestroyAPIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    queryset = Organization.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = OrganizationSerializer

    redirect_route = "organizations-dashboard"
    redirect_kwarg = "pk"

    def delete(self, request, *args, **kwargs):
        return super(OrganizationDeleteAPI, self).delete(request, *args, **kwargs)


@method_decorator(
    name="get",
    decorator=swagger_auto_schema(
        tags=["Invites"],
        operation_summary="Get organization invite link",
        operation_description="Get a link to use to invite a new member to an organization in AiXBlock.",
        responses={200: OrganizationInviteSerializer()},
    ),
)
class OrganizationInviteAPI(APIView):
    parser_classes = (JSONParser,)
    permission_required = all_permissions.organizations_change

    def get(self, request, *args, **kwargs):
        org = get_object_with_check_and_log(
            self.request, Organization, pk=request.user.active_organization_id
        )
        self.check_object_permissions(self.request, org)
        invite_url = ""
        if hasattr(settings, "FORCE_SCRIPT_NAME") and settings.FORCE_SCRIPT_NAME:
            invite_url = invite_url.replace(settings.FORCE_SCRIPT_NAME, "", 1)
        serializer = OrganizationInviteSerializer(
            data={"invite_url": invite_url, "token": org.token}
        )
        serializer.is_valid()
        return Response(serializer.data, status=200)


@method_decorator(
    name="post",
    decorator=swagger_auto_schema(
        tags=["Invites"],
        operation_summary="Invite by upload file csv",
        operation_description="Invite new members to an organization in AiXBlock by upload csv.",
        responses={200: "upload success"},
        manual_parameters=[
            openapi.Parameter(
                "csv_file",
                openapi.IN_FORM,
                type=openapi.TYPE_FILE,
                description="Document to be uploaded",
            ),
            openapi.Parameter(
                "username",
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description="username",
            ),
            openapi.Parameter(
                "email", openapi.IN_FORM, type=openapi.TYPE_STRING, description="email"
            ),
            openapi.Parameter(
                "role", openapi.IN_FORM, type=openapi.TYPE_STRING, description="role"
            ),
            openapi.Parameter(
                "organizationId",
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description="organizationId",
            ),
        ],
    ),
)
class OrganizationInviteAPIByCSV(APIView):
    parser_classes = (
        MultiPartParser,
        FileUploadParser,
    )
    permission_required = all_permissions.organizations_change

    def post(self, request):
        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        project_id = request.data["project_id"].strip()

        if "csv_file" not in request.FILES:
            chars = "abcdefghijklmnopqrstuvwxyz0123456789"
            random_password = "".join(random.choice(chars) for _ in range(8))
            email = request.data["email"].strip().lower()
            username = request.data["username"].strip()
            role = request.data["role"].strip()
            project_id = request.data["project_id"].strip()

            is_qa = True if role == "qa" else False
            is_qc = True if role == "qc" else False
            is_labeler = True if role =="annotator" else False

            if not username or len(username) == 0:
                raise ValidationError({"username": ["this field is required"]})

            if not email or not re.match(email_regex, email) is not None:
                raise ValidationError({"email": ["must be a valid email address"]})

            if not request.data["organizationId"]:
                raise ValidationError({"organizationId": ["Organization is not specified"]})

            org = Organization.objects.get(pk=request.data["organizationId"])
            if not OrganizationMember.objects.filter(user=request.user, organization=org, is_admin=True).exists() and not request.user.is_superuser:
                raise PermissionDenied("No permission to invite members to this organization")

            if not org:
                raise ValidationError(
                    {
                        "organizationId": [
                            f"Organization #{request.data['organizationId']} not found"
                        ]
                    }
                )

            user = User.objects.filter(email=email).first()

            if not user:
                username_check = User.objects.filter(username=username).first()

                if username_check:
                    raise ValidationError(
                        {"username": ["this username has been taken"]}
                    )

                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=random_password,
                    is_active=True,
                    is_staff=(role == "staff" or role == "admin"),
                    is_qa=True if role == "qa" else False,
                    is_qc=True if role == "qc" else False,
                    is_superuser=False,
                    active_organization=org,
                )
                try:
                    token = create_hash()
                    team_id = create_hash()
                    status = "actived"
                    org_user = Organization.objects.create(
                        title=email,
                        created_by=user,
                        token=token,
                        team_id=team_id,
                        status=status
                    )
                    OrganizationMember.objects.create(organization=org_user, user=user, is_admin=True)
                except Exception as e:
                    print(e)

            membership = OrganizationMember.objects.filter(
                user=user, organization=org
            ).first()

            if membership:
                return Response(
                    {"message": "User has been added to organization already"},
                    status=400,
                )

            if not project_id:
                orgmem = OrganizationMember.objects.create(user=user, organization=org, is_admin = (role == "admin"), level_org=True)
            else:
                orgmem = OrganizationMember.objects.create(user=user, organization=org, is_admin = (role == "admin"), level_org=False)
                Organization_Project_Permission.objects.create(organization=org, user=user, project_id_id=int(project_id), is_qa=is_qa, is_qc=is_qc)
                
            orgmem.save()

            send_to = user.username if user.username else user.email
            author_invite = request.user.username if request.user.username else request.user.email
            html_file_path =  './templates/mail/add_org_member.html'

            with open(html_file_path, 'r', encoding='utf-8') as file:
                html_content = file.read()

            html_content = html_content.replace('[user]', f'{send_to}')
            html_content = html_content.replace('[author]', f'{author_invite}')
            html_content = html_content.replace('[random_password]', f'{random_password}')

            domain_reset = settings.BASE_BACKEND_URL
            if "Origin" in self.request.headers and self.request.headers["Origin"] != domain_reset:
                domain_reset = self.request.headers["Origin"]

            html_content = html_content.replace('[Login Link]', f'{domain_reset}/user/login/')

            data = {
                "subject": "Welcome to AIxBlock - Registration Successful!",
                "from": "noreply@aixblock.io",
                "to": [f"{email}"],
                "html": html_content,
                "text": "Welcome to AIxBlock!",
                "attachments": []
            }

            docket_api = "tcp://69.197.168.145:4243"
            host_name = MAIL_SERVER

            email_thread = threading.Thread(target=send_email_thread, args=(docket_api, host_name, data,))
            email_thread.start()

            return Response({"password": random_password}, status=200)

        csv_file = request.FILES["csv_file"].read().decode("utf-8").splitlines()
        csv_reader = csv.reader(csv_file)
       
        if csv_reader == None:
            csv_file = request.FILES["csv_file"].read().decode("utf-8").splitlines("\n")
            csv_reader = csv.reader(csv_file)
        can_specify_org = request.user.is_superuser or request.user.is_staff
        counter = 0
        missing_information_count = 0
        new_users_count = 0
        added_already_count = 0

        for row in csv_reader:
            
            if ";" in row[0] and len(row)< 5:
                row = row[0].split(";")
            print(row)
            counter += 1
            columns_count = len(row)
            username = row[0].strip() if columns_count > 0 else ""
            email = row[1].strip().lower() if columns_count > 1 else ""
            password = row[2].strip() if columns_count > 2 else ""
            role = row[4].strip() if columns_count > 4 else ""
            org_id = 0

            if can_specify_org and columns_count > 3:
                org_id = int(row[3])

            if org_id < 1:
                org_id = request.user.active_organization_id

            org_id = request.user.active_organization_id
            org = Organization.objects.get(pk=org_id)
            if not OrganizationMember.objects.filter(user=request.user, organization=org, is_admin=True).exists() and not request.user.is_superuser:
                raise PermissionDenied("No permission to invite members to this organization")

            if (
                not email
                or not username
                or not password
                or not org
                or not re.match(email_regex, email) is not None
            ):
                missing_information_count += 1
                continue

            user = User.objects.filter(email=email).first()

            if not user:
                username_check = User.objects.filter(username=username).first()

                if username_check:
                    missing_information_count += 1
                    continue

                new_users_count += 1
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    is_active=True,
                    is_staff=(role == "staff" or role == "admin"),
                    is_qa=True if role == "qa" else False,
                    is_qc=True if role == "qc" else False,
                    is_superuser=False,
                    active_organization=org,
                )

                try:
                    token = create_hash()
                    team_id = create_hash()
                    status = "actived"
                    org_user = Organization.objects.create(
                        title=email,
                        created_by=user,
                        token=token,
                        team_id=team_id,
                        status=status
                    )
                    OrganizationMember.objects.create(organization=org_user, user=user, is_admin=True)

                except Exception as e:
                    print(e)

                send_to = user.username if user.username else user.email
                author_invite = request.user.username if request.user.username else request.user.email

                html_file_path =  './templates/mail/add_org_member.html'

                with open(html_file_path, 'r', encoding='utf-8') as file:
                    html_content = file.read()

                html_content = html_content.replace('[user]', f'{send_to}')
                html_content = html_content.replace('[author]', f'{author_invite}')
                html_content = html_content.replace('[random_password]', f'{password}')

                domain_reset = settings.BASE_BACKEND_URL
                if "Origin" in self.request.headers and self.request.headers["Origin"] != domain_reset:
                    domain_reset = self.request.headers["Origin"]

                html_content = html_content.replace('[Login Link]', f'{domain_reset}/user/login/')

                data = {
                    "subject": "Welcome to AIxBlock - Registration Successful!",
                    "from": "noreply@aixblock.io",
                    "to": [f"{email}"],
                    "html": html_content,
                    "text": "Welcome to AIxBlock!",
                    "attachments": []
                }

                docket_api = "tcp://69.197.168.145:4243"
                host_name = MAIL_SERVER

                email_thread = threading.Thread(target=send_email_thread, args=(docket_api, host_name, data,))
                email_thread.start()

            membership = OrganizationMember.objects.filter(
                user=user, organization=org
            ).first()

            if membership:
                added_already_count += 1
                continue

            if not project_id:
                orgmem = OrganizationMember.objects.create(user=user, organization=org, is_admin = (role == "admin"), level_org=True)
            else:
                orgmem = OrganizationMember.objects.create(user=user, organization=org, is_admin = (role == "admin"), level_org=False)
                Organization_Project_Permission.objects.create(organization=org, user=user, project_id_id=int(project_id), is_qa=is_qa, is_qc=is_qc)
                
            orgmem.save()

        return Response(
            {
                "detail": f"File has been processed successfully. "
                f"Total: {counter} "
                f"/ Failed: {missing_information_count} "
                f"/ New user: {new_users_count} "
                f"/ Already in organization: {added_already_count}."
            },
            status=200,
        )


@method_decorator(
    name="post",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="remove member in an organization",
        operation_description="",
        responses={200: "success"},
        manual_parameters=[
            openapi.Parameter(
                "memberId",
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description="memberId",
            ),
            openapi.Parameter(
                "organizationId",
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description="organizationId",
            ),
        ],
    ),
)
class OrganizationRemoveMemberAPI(APIView):
    parser_classes = (
        FormParser,
        MultiPartParser,
    )
    permission_required = all_permissions.organizations_change

    def post(self, request, *args, **kwargs):
        user = User.objects.filter(pk=request.data["memberId"]).first()
        project_id = request.data.get("project_id", None)
        organization_member = OrganizationMember.objects.filter(
            organization=request.data["organizationId"], user=user
        ).first()

        if project_id:
            org_project = Organization_Project_Permission.objects.filter(organization_id=organization_member.organization_id, project_id_id=project_id, user=user).delete()
        else:
            org_project = Organization_Project_Permission.objects.filter(organization_id=organization_member.organization_id, user=user).delete()

        org_project_now = Organization_Project_Permission.objects.filter(organization_id=organization_member.organization_id)

        if organization_member != None and user != None and not org_project_now:
            organization_member.delete()
        
        if not Organization.objects.filter(created_by=user).exists():
            try:
                    token = create_hash()
                    team_id = create_hash()
                    status = "actived"
                    org_user = Organization.objects.create(
                        title=user.email,
                        created_by=user,
                        token=token,
                        team_id=team_id,
                        status=status
                    )
                    OrganizationMember.objects.create(organization=org_user, user=user, is_admin=True)
            except Exception as e:
                print(e)
                
        return Response({"status": "Success removed"}, status=200)


@method_decorator(
    name="post",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="add member into an organization by email",
        operation_description="",
        responses={200: "success"},
        manual_parameters=[
            openapi.Parameter(
                "email", openapi.IN_FORM, type=openapi.TYPE_STRING, description="email"
            ),
            openapi.Parameter(
                "organizationId",
                openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description="organizationId",
            ),
        ],
    ),
)
class OrganizationAddMemberByEmailAPI(APIView):
    parser_classes = (MultiPartParser,)
    permission_required = all_permissions.organizations_change

    def post(self, request, *args, **kwargs):
        if "email" not in request.data:
            return Response({"detail": f"Please provide the email address"}, status=400)

        if "organizationId" not in request.data:
            return Response({"detail": f"Please provide the organization"}, status=400)

        project_id = request.data["project_id"]
        
        role = request.data["role"].strip()
        
        user = User.objects.filter(email=request.data["email"].lower()).first()

        if not user:
            return Response(
                {
                    "detail": f'User with the email {request.data["email"]} not found',
                    "missing": True,
                },
                status=400,
            )

        org = Organization.objects.get(pk=request.data["organizationId"])

        if not org:
            return Response(
                {"detail": f'Organization #{request.data["organizationId"]} not found'},
                status=400,
            )

        user.is_qa = True if role == "qa" else False
        user.is_qc = True if role == "qc" else False
        is_qa = True if role == "qa" else False
        is_qc = True if role == "qc" else False
        is_labeler = True if role =="annotator" else False
        user.save()

        organization_member = OrganizationMember.objects.filter(
            organization=request.data["organizationId"], user=user
        ).first()

        if organization_member == None and user != None:
            if not project_id:
                orgmem = OrganizationMember.objects.create(user=user, organization=org, is_admin = (role == "admin"),  level_org=True)
            else:
                orgmem = OrganizationMember.objects.create(user=user, organization=org, is_admin = (role == "admin"), level_org=False)
                Organization_Project_Permission.objects.create(organization=org, user=user, project_id_id=int(project_id), is_qa=is_qa, is_qc=is_qc)
            orgmem.save()
        else:
            if project_id:
                Organization_Project_Permission.objects.create(organization=org, user=user, project_id_id=int(project_id), is_qa=is_qa, is_qc=is_qc)

        return Response(
            {"detail": "User has been added to organization successfully"}, status=200
        )


@method_decorator(
    name="post",
    decorator=swagger_auto_schema(
        tags=["Invites"],
        operation_summary="Reset organization token",
        operation_description="Reset the token used in the invitation link to invite someone to an organization.",
        responses={200: OrganizationInviteSerializer()},
    ),
)
class OrganizationResetTokenAPI(APIView):
    permission_required = all_permissions.organizations_invite
    parser_classes = (JSONParser,)

    def post(self, request, *args, **kwargs):
        org = request.user.active_organization
        org.reset_token()
        logger.debug(f"New token for organization {org.pk} is {org.token}")
        invite_url = ""
        serializer = OrganizationInviteSerializer(
            data={"invite_url": invite_url, "token": org.token}
        )
        serializer.is_valid()
        return Response(serializer.data, status=201)


@method_decorator(
    name="get",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Get organization project",
        operation_description="Retrieve the projects for a specific organization by ID.",
    ),
)
class OrganizationProjectAPI(APIView):
    queryset = Organization.objects.all()
    permission_classes = (IsAuthenticated,)
    permission_required = all_permissions.organizations_view

    def get(self, request, *args, **kwargs):
        print(kwargs)
        projects = Project.objects.filter(organization_id=kwargs["pk"]).order_by("id")
        from django.core import serializers
        from django.http import HttpResponse

        json = serializers.serialize("json", projects)
        return HttpResponse(json, content_type="application/json")


@method_decorator(
    name="get",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Get organization users",
        operation_description="Retrieve the users for a specific organization by ID.",
    ),
)
class OrganizationUserAPI(generics.ListAPIView):
    permission_classes = (IsAuthenticated,)
    permission_required = all_permissions.organizations_view
    pagination_class = SetPagination
    serializer_class = UserAdminViewSerializer

    def get_queryset(self):
        org_id = self.request.user.active_organization_id
        return User.objects.filter(active_organization_id=org_id).order_by("id")

    def get(self, request, *args, **kwargs):
        return super(OrganizationUserAPI, self).get(request, *args, **kwargs)


@method_decorator(
    name="get",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Get organization report",
        operation_description="Retrieve the report for a specific organization by ID.",
    ),
)
@method_decorator(
    name="post",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Get projects in organization by organization by ID",
        operation_description="",
        request_body=OrganizationReporRequest,
        responses={
            200: openapi.Response(
                title="Get projects in organization OK",
                description="Get projects in organization has succeeded.",
            ),
        },
    ),
)
class OrganizationReportAPI(generics.RetrieveAPIView):
    queryset = Organization.objects.all()
    permission_classes = (IsAuthenticated,)
    permission_required = all_permissions.organizations_view

    def get(self, request, *args, **kwargs):
        pk_org = kwargs["pk"]
        pk_project = kwargs["pro"]
        role = kwargs["rol"]
        projects = Project.objects.filter(organization=pk_org)
        if int(pk_project) > 0:
            projects = projects.filter(id__in=[pk_project])
        response = HttpResponse(content_type="text/csv")
        filename = f'organization_{pk_org}_report_{datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.csv'
        response["Content-Disposition"] = f'attachment; filename="{filename}"'

        writer = csv.DictWriter(
            response,
            delimiter="|",
            fieldnames=[
                "id",
                "project",
                "data",
                "duration",
                "channels",
                "meta",
                "annotators",
                "pool",
                "reviewed_by",
                "reviewed_result",
                "created_at",
            ],
        )

        writer.writeheader()

        for project in projects:
            tasks = Task.objects.filter(project_id=project.id).order_by("id")

            for task in tasks:
                annotators = []
                data = copy.deepcopy(task.data)
                duration = None
                channels = None

                for annotation in task.completed_annotations:
                    annotators.append(annotation.completed_by.email)

                if "duration" in data:
                    duration = data["duration"]
                    del data["duration"]

                if "channels" in data:
                    channels = data["channels"]
                    del data["channels"]

                if "image" in data:
                    image = data["image"]
                    if "/data/upload" in image:
                        data["image"] = f"{HOSTNAME}{image}"
                    else:
                        data["image"] = image
                if "pcd" in data:
                    pcd = data["pcd"]
                    if "/data/upload" in pcd:
                        data["pcd"] = f"{HOSTNAME}{pcd}"
                    else:
                        data["pcd"] = pcd
                if "audio" in data:
                    audio = data["audio"]
                    if "/data/upload" in audio:
                        data["audio"] = f"{HOSTNAME}{audio}"
                    else:
                        data["audio"] = audio
                if "captioning" in data:
                    captioning = data["captioning"]
                    if "/data/upload" in captioning:
                        data["captioning"] = f"{HOSTNAME}{captioning}"
                    else:
                        data["captioning"] = captioning
                if task.reviewed_by != None:
                    user = User.objects.filter(email=task.reviewed_by)
                    print(user)
                    if user != None:
                        user = user.first()
                        if role == "is_qc" and user.is_qc == True:
                            writer.writerow(
                                {
                                    "id": task.id,
                                    "project": project.title,
                                    "data": data,
                                    "duration": duration,
                                    "channels": channels,
                                    "meta": task.meta,
                                    "annotators": ",".join(annotators),
                                    "pool": "QA" if task.is_in_review else "",
                                    "reviewed_by": task.reviewed_by,
                                    "reviewed_result": task.reviewed_result,
                                    "created_at": task.created_at,
                                }
                            )
                        elif role == "is_qa" and user.is_qa == True:
                            writer.writerow(
                                {
                                    "id": task.id,
                                    "project": project.title,
                                    "data": data,
                                    "duration": duration,
                                    "channels": channels,
                                    "meta": task.meta,
                                    "annotators": ",".join(annotators),
                                    "pool": "QA" if task.is_in_review else "",
                                    "reviewed_by": task.reviewed_by,
                                    "reviewed_result": task.reviewed_result,
                                    "created_at": task.created_at,
                                }
                            )
                        elif role == "is_annotator" and user.is_annotator == True:
                            writer.writerow(
                                {
                                    "id": task.id,
                                    "project": project.title,
                                    "data": data,
                                    "duration": duration,
                                    "channels": channels,
                                    "meta": task.meta,
                                    "annotators": ",".join(annotators),
                                    "pool": "QA" if task.is_in_review else "",
                                    "reviewed_by": task.reviewed_by,
                                    "reviewed_result": task.reviewed_result,
                                    "created_at": task.created_at,
                                }
                            )
                            print("is_annotator")
                        elif role == "all":
                            writer.writerow(
                                {
                                    "id": task.id,
                                    "project": project.title,
                                    "data": data,
                                    "duration": duration,
                                    "channels": channels,
                                    "meta": task.meta,
                                    "annotators": ",".join(annotators),
                                    "pool": "QA" if task.is_in_review else "",
                                    "reviewed_by": task.reviewed_by,
                                    "reviewed_result": task.reviewed_result,
                                    "created_at": task.created_at,
                                }
                            )
        return response

    def post(self, request, *args, **kwargs):
        j_obj = json.loads(request.body)
        print(request.body)
        print(request.POST)
        pk_org = kwargs["pk"]
        pk_project = j_obj["project_id"]
        role = j_obj["roles"]
        projects = Project.objects.filter(organization=pk_org)
        if int(pk_project) > 0:
            projects = projects.filter(id__in=[pk_project])
        response = HttpResponse(content_type="text/csv")
        filename = f'organization_{pk_org}_report_{datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.csv'
        response["Content-Disposition"] = f'attachment; filename="{filename}"'

        writer = csv.DictWriter(
            response,
            delimiter="|",
            fieldnames=[
                "id",
                "project",
                "data",
                "duration",
                "channels",
                "meta",
                "annotators",
                "pool",
                "reviewed_by",
                "reviewed_result",
                "created_at",
            ],
        )

        writer.writeheader()

        for project in projects:
            tasks = Task.objects.filter(project_id=project.id).order_by("id")

            for task in tasks:
                annotators = []
                data = copy.deepcopy(task.data)
                duration = None
                channels = None

                for annotation in task.completed_annotations:
                    annotators.append(annotation.completed_by.email)

                if "duration" in data:
                    duration = data["duration"]
                    del data["duration"]

                if "channels" in data:
                    channels = data["channels"]
                    del data["channels"]

                if "image" in data:
                    image = data["image"]
                    if "/data/upload" in image:
                        data["image"] = f"{HOSTNAME}{image}"
                    else:
                        data["image"] = image
                if "pcd" in data:
                    pcd = data["pcd"]
                    if "/data/upload" in pcd:
                        data["pcd"] = f"{HOSTNAME}{pcd}"
                    else:
                        data["pcd"] = pcd
                if "audio" in data:
                    audio = data["audio"]
                    if "/data/upload" in audio:
                        data["audio"] = f"{HOSTNAME}{audio}"
                    else:
                        data["audio"] = audio
                if "captioning" in data:
                    captioning = data["captioning"]
                    if "/data/upload" in captioning:
                        data["captioning"] = f"{HOSTNAME}{captioning}"
                    else:
                        data["captioning"] = captioning
                if task.reviewed_by != None:
                    user = User.objects.filter(email=task.reviewed_by)
                    print(user)
                    if user != None:
                        user = user.first()
                        if role == "is_qc" and user.is_qc == True:
                            writer.writerow(
                                {
                                    "id": task.id,
                                    "project": project.title,
                                    "data": data,
                                    "duration": duration,
                                    "channels": channels,
                                    "meta": task.meta,
                                    "annotators": ",".join(annotators),
                                    "pool": "QA" if task.is_in_review else "",
                                    "reviewed_by": task.reviewed_by,
                                    "reviewed_result": task.reviewed_result,
                                    "created_at": task.created_at,
                                }
                            )
                        elif role == "is_qa" and user.is_qa == True:
                            writer.writerow(
                                {
                                    "id": task.id,
                                    "project": project.title,
                                    "data": data,
                                    "duration": duration,
                                    "channels": channels,
                                    "meta": task.meta,
                                    "annotators": ",".join(annotators),
                                    "pool": "QA" if task.is_in_review else "",
                                    "reviewed_by": task.reviewed_by,
                                    "reviewed_result": task.reviewed_result,
                                    "created_at": task.created_at,
                                }
                            )
                        elif role == "is_annotator" and user.is_annotator == True:
                            writer.writerow(
                                {
                                    "id": task.id,
                                    "project": project.title,
                                    "data": data,
                                    "duration": duration,
                                    "channels": channels,
                                    "meta": task.meta,
                                    "annotators": ",".join(annotators),
                                    "pool": "QA" if task.is_in_review else "",
                                    "reviewed_by": task.reviewed_by,
                                    "reviewed_result": task.reviewed_result,
                                    "created_at": task.created_at,
                                }
                            )
                            print("is_annotator")
                        elif role == "all":
                            writer.writerow(
                                {
                                    "id": task.id,
                                    "project": project.title,
                                    "data": data,
                                    "duration": duration,
                                    "channels": channels,
                                    "meta": task.meta,
                                    "annotators": ",".join(annotators),
                                    "pool": "QA" if task.is_in_review else "",
                                    "reviewed_by": task.reviewed_by,
                                    "reviewed_result": task.reviewed_result,
                                    "created_at": task.created_at,
                                }
                            )
        return response


@method_decorator(
    name="get",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="List organizations for Admin",
        operation_description="""
        Return a list of the organizations from admin view.
        """,
    ),
)
class OrganizationListAdminViewAPI(generics.ListAPIView):
    parser_classes = (JSONParser, MultiPartParser, FormParser)
    permission_classes = (AllowAny,)
    pagination_class = SetPagination
    serializer_class = OrganizationSerializer

    def get_queryset(self):
        return Organization.objects.order_by("-id")

    def get(self, *args, **kwargs):
        return super(OrganizationListAdminViewAPI, self).get(*args, **kwargs)


@method_decorator(
    name="post",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Create organization",
        operation_description="Create organization.",
    ),
)
class OrganizationCreateAPI(generics.CreateAPIView):
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    permission_required = ViewClassPermission(
        POST=all_permissions.organizations_create,
    )
    serializer_class = OrganizationSerializer

    def perform_create(self, serializer):
        user_id = self.request.user.id
        serializer.save(created_by_id=user_id)

    def post(self, request, *args, **kwargs):
        return super(OrganizationCreateAPI, self).post(request, *args, **kwargs)


@method_decorator(
    name="get",
    decorator=swagger_auto_schema(
        tags=["Organizations"],
        operation_summary="Get role user in project",
        operation_description="",
        manual_parameters=[
            openapi.Parameter(name="project_id", in_=openapi.IN_QUERY, type=openapi.TYPE_INTEGER, required=False)
        ],
    ),
)
class RoleUserInProjectAPI(APIView):
    def get(self, request, *args, **kwargs):
        project_id = self.request.query_params["project_id"]
        user = self.request.user
        user_permission = Organization_Project_Permission.objects.filter(project_id=project_id, user_id=user.id, deleted_at__isnull=True).order_by("-id").first()
        if user_permission:
            response = {
                "is_qa": user_permission.is_qa,
                "is_qc": user_permission.is_qc
            }
        else:
            return Response(None, status=201)
        
        return Response(response, status=200)

