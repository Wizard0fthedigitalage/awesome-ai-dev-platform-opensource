
"""This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license.
"""
import logging

from rest_framework import generics
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied, ValidationError
from drf_yasg.utils import swagger_auto_schema
from corsheaders.decorators import cors_headers  # Added for CORS control

from core.permissions import all_permissions, permission_org
from core.utils.common import get_object_with_check_and_log
from projects.models import Project
from core.permissions import IsSuperAdminOrg
from organizations.models import OrganizationMember

logger = logging.getLogger(__name__)

@cors_headers(
    origins=["https://workflow-live.aixblock.io", "https://app.aixblock.io"],
    methods=["GET", "POST"],
    headers=["Content-Type", "Authorization"],
    credentials=True
)
class ConfirmationTokensListAPI(generics.ListCreateAPIView):
    """List or create confirmation tokens for a project"""
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    permission_required = all_permissions.projects_change

    def get_queryset(self):
        project_pk = self.request.query_params.get('project')
        project = get_object_with_check_and_log(self.request, Project, pk=project_pk)
        self.check_object_permissions(self.request, project)
        return []  # Simulated queryset (replace with actual model)

    def post(self, request, *args, **kwargs):
        project = Project.objects.get(id=self.request.data.get('project'))
        check_org_admin = OrganizationMember.objects.filter(
            organization_id=project.organization_id,
            user_id=self.request.user.id, is_admin=True
        ).exists()
        
        if not check_org_admin and not self.request.user.is_superuser:
            raise ValidationError("You do not have permission to setup this project", code=403)

        try:
            # Simulated token creation (replace with actual logic)
            token_data = {"message": "Token created", "data": request.data}
            return Response(token_data)
        except Exception as e:
            print(e)
            raise ValidationError("Error creating token", code=500)

@cors_headers(
    origins=["https://workflow-live.aixblock.io", "https://app.aixblock.io"],
    methods=["GET", "PUT", "DELETE"],
    headers=["Content-Type", "Authorization"],
    credentials=True
)
class ConfirmationTokensDetailAPI(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a confirmation token by ID"""
    parser_classes = (JSONParser, FormParser, MultiPartParser)
    permission_required = all_permissions.projects_change
    permission_classes = [IsSuperAdminOrg]

    def get_object(self):
        project = Project.objects.get(id=self.request.query_params.get('project'))
        if not permission_org(self.request.user, project):
            raise PermissionDenied("User lacks organization permissions")
        return {}  # Simulated object (replace with actual model)

    @swagger_auto_schema(auto_schema=None)
    def put(self, request, *args, **kwargs):
        try:
            # Simulated update (replace with actual logic)
            return Response({"message": "Token updated"})
        except Exception as e:
            print(e)
            raise ValidationError("Error updating token", code=500)
