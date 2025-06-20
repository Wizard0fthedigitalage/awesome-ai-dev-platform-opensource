"""
This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license.
"""
import logging
from rest_framework import generics
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import UserRateThrottle
from drf_yasg.utils import swagger_auto_schema
from django.conf import settings
from django.db.models import Q
from projects.models import Project
from users.models import User
from .models import Task
from .serializers import TaskSerializer

logger = logging.getLogger(__name__)

class TaskThrottle(UserRateThrottle):
    """Custom throttle for /api/tasks/ endpoint"""
    rate = '10/minute'  # Limit to 10 requests per minute per user

class IsTaskOwnerOrAdmin:
    """Custom permission to allow task owners or admins"""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        # Allow task owner or admin
        user = request.user
        if obj.user_id == user.id:
            return True
        if user.is_superuser or user.is_staff:  # Admins are superusers or staff
            return True
        logger.warning(
            f"User {user.id} attempted unauthorized access to task {obj.id} for project {obj.project.id}"
        )
        return False

def get_object_with_check_and_log(request, model, **kwargs):
    """Retrieve object with permission check and logging"""
    try:
        obj = model.objects.get(**kwargs)
        # Check if user has access to the project (created by or assigned to user)
        if hasattr(obj, 'created_by') and obj.created_by_id != request.user.id and not request.user.is_superuser and not request.user.is_staff:
            logger.warning(f"User {request.user.id} attempted unauthorized access to {model.__name__} {kwargs}")
            raise PermissionDenied("User lacks project permissions")
        return obj
    except model.DoesNotExist:
        logger.warning(f"User {request.user.id} requested non-existent {model.__name__} {kwargs}")
        raise NotFound(f"{model.__name__} not found")

class TaskListAPI(generics.ListAPIView):
    parser_classes = (JSONParser,)
    permission_classes = [IsAuthenticated, IsTaskOwnerOrAdmin]
    serializer_class = TaskSerializer
    throttle_classes = [TaskThrottle]

    def get_queryset(self):
        """
        Return tasks accessible to the user based on their role.
        Regular users see only their own tasks; admins see all tasks in a project.
        """
        user = self.request.user
        project_id = self.request.query_params.get('project')
        
        if not project_id:
            logger.warning(f"User {user.id} attempted to list tasks without project ID")
            return Task.objects.none()

        try:
            project = get_object_with_check_and_log(self.request, Project, pk=project_id)
            # Admins can see all tasks in the project
            if user.is_superuser or user.is_staff:
                queryset = Task.objects.filter(project_id=project.id)
            else:
                # Regular users can only see their own tasks
                queryset = Task.objects.filter(project_id=project.id, user_id=user.id)
            
            return queryset
        except Project.DoesNotExist:
            logger.warning(f"User {user.id} requested non-existent project {project_id}")
            raise NotFound("Project not found")

    @swagger_auto_schema(
        operation_description="Retrieve tasks for a specific project, restricted to task owner or admin.",
        responses={
            200: TaskSerializer(many=True),
            403: "Permission Denied",
            404: "Project not found"
        }
    )
    def get(self, request, *args, **kwargs):
        """Handle GET requests to /api/tasks/"""
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True, context={'user': request.user})
            logger.info(f"User {request.user.id} successfully retrieved tasks for project {request.query_params.get('project')}")
            return Response({'tasks': serializer.data})
        except Exception as e:
            logger.error(f"Error retrieving tasks for user {request.user.id}: {str(e)}")
            raise

class TaskDetailAPI(generics.RetrieveAPIView):
    """Retrieve a single task by ID"""
    parser_classes = (JSONParser,)
    permission_classes = [IsAuthenticated, IsTaskOwnerOrAdmin]
    serializer_class = TaskSerializer
    throttle_classes = [TaskThrottle]

    def get_queryset(self):
        """Restrict queryset to tasks accessible by user"""
        user = self.request.user
        if user.is_superuser or user.is_staff:
            return Task.objects.all()
        return Task.objects.filter(user_id=user.id)

    def get_object(self):
        """Override to add permission check"""
        obj = super().get_object()
        if not self.request.user.is_superuser and not self.request.user.is_staff and obj.user_id != self.request.user.id:
            logger.warning(
                f"User {self.request.user.id} attempted unauthorized access to task {obj.id} for project {obj.project.id}"
            )
            raise PermissionDenied("User lacks permissions for this task")
        return obj

    @swagger_auto_schema(
        operation_description="Retrieve a specific task by ID, restricted to task owner or admin.",
        responses={
            200: TaskSerializer(),
            403: "Permission Denied",
            404: "Task not found"
        }
    )
    def get(self, request, *args, **kwargs):
        """Handle GET requests for a single task"""
        try:
            task = self.get_object()
            serializer = self.get_serializer(task, context={'user': request.user})
            logger.info(f"User {request.user.id} successfully retrieved task {task.id}")
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error retrieving task for user {request.user.id}: {str(e)}")
            raise
