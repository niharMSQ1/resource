import json
import requests
import uuid
import boto3

from django.http import JsonResponse
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.views.decorators.http import require_POST
from oauthlib.common import generate_token
from rest_framework_simplejwt.tokens import RefreshToken as RT
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status, permissions
from oauth2_provider.models import Application, AccessToken, RefreshToken, IDToken
from oauth2_provider.decorators import protected_resource
from django.conf import settings
from django.utils import timezone
from .utils import generate_base64_string
from .token_utils import generate_access_token, generate_refresh_token
from.models import User, IAMUser

@csrf_exempt
@require_POST
def user_registration(request):
    """
    Registers a new user with the provided username, password, and email.
    
    Request:
        POST request with JSON data containing 'username', 'password', and 'email'.
    
    Response:
        - 201 Created: User registered successfully.
        - 400 Bad Request: Invalid JSON data.
        - 409 Conflict: User already exists or email already registered.
        - 500 Internal Server Error: Other errors occurred during registration.
    """
    try:
        data = json.loads(request.body.decode('utf-8'))
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')

        if not all([username, password, email]):
            raise ValueError('Incomplete data. Please provide username, password, and email.')

        if User.objects.filter(username=username).exists():
            raise IntegrityError('User already exists.')
        
        if User.objects.filter(email=email).exists():
            raise IntegrityError('Email already exists.')

        user = User.objects.create_user(username=username, password=password, email=email)

        return JsonResponse({'message': 'User registered successfully.'}, status=status.HTTP_201_CREATED)
    
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data.'}, status=status.HTTP_400_BAD_REQUEST)

    except IntegrityError as e:
        return JsonResponse({'error': str(e)}, status=status.HTTP_409_CONFLICT)

    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return JsonResponse({'error': f'Error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
@require_POST
def user_login(request):
    """
    Logs in a user with provided username and password.
    
    Request:
        POST request with JSON data containing 'username' and 'password'.
    
    Response:
        - Successful login:
            Returns JSON with JWT access and refresh tokens along with OAuth access and refresh tokens.
        - 400 Bad Request: Invalid JSON data.
        - 401 Unauthorized: Invalid credentials.
        - 500 Internal Server Error: Other errors occurred during login.
    """
    try:
        # Load JSON data from the request body
        data = json.loads(request.body.decode('utf-8'))
        username = data.get('username')

        # Check if the username exists
        if not User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'User does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        password = data.get('password')
        user = authenticate(request, username=username, password=password)

        # Check if authentication failed
        if user is None:
            return JsonResponse({'error': 'Login unsuccessful. Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Delete existing OAuth tokens
        AccessToken.objects.filter(user=user).delete()
        RefreshToken.objects.filter(user=user).delete()

        # Generate new OAuth tokens
        refresh = RT.for_user(user)
        headers = {'Authorization': f'Bearer {str(refresh.access_token)}'}
        create_oauth_refresh_token = requests.post("http://127.0.0.1:8001/api/generate-token/", headers=headers)

        # Return the response with new tokens
        return JsonResponse({
            "jwt_refresh_token": str(refresh),
            "jwt_access_token": str(refresh.access_token),
            "oauth_refresh_token": (create_oauth_refresh_token.json())['refresh_token'],
            "oauth_access_token": (create_oauth_refresh_token.json())['access_token'],
        })

    except json.JSONDecodeError:
        # Handle JSON decoding error
        return JsonResponse({'error': 'Invalid JSON data.'}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        # Handle other exceptions
        return JsonResponse({'error': f'Error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def generate_token_endpoint(request):
    """
    Generates OAuth tokens for an authenticated user.
    
    Request:
        POST request authenticated with JWT.
    
    Response:
        Returns JSON with new OAuth access and refresh tokens.
    """
    username = request.user.username
    password = request.user.password
    client_id = settings.CLIENT_ID

    try:
        application = Application.objects.get(client_id=client_id)
    except Application.DoesNotExist:
        return JsonResponse({'error': 'Invalid client credentials'}, status=401)

    user = User.objects.get(username=username)
    if user.password == password:
        if user is not None:
            AccessToken.objects.filter(user=user, application=application).delete() # deleting if I am calling the current api separately, otherwise this line is not required
            RefreshToken.objects.filter(user=user, application=application).delete() # deleting if I am calling the current api separately, otherwise this line is not required

            expires = timezone.now() + timezone.timedelta(seconds=1)
            expires_iso = expires.isoformat()

            new_uuid = uuid.uuid4()
            id_token = IDToken.objects.create(jti=new_uuid, expires=expires)

            access_token = AccessToken.objects.create(
                user=user,
                application=application,
                token=generate_token(),
                expires=expires_iso,
                id_token=id_token,
            )

            refresh_token = RefreshToken.objects.create(
                user=user,
                application=application,
                token=generate_token(),
                access_token=access_token,
            )

            response_data = {
                'access_token': access_token.token,
                'token_type': 'Bearer',
                'expires_in': (expires - timezone.now()).total_seconds(),
                'refresh_token': refresh_token.token,
            }

            return JsonResponse(response_data)
        else:
            return JsonResponse({'error': 'Invalid user credentials'}, status=401)


'''
This particular API has to be called to obtain the new oAuth access token from
the existing oauth refresh token, there's no need for this because we'll be 
calling this API internally, for testing purpose we can hit it with JWT access token.
'''
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def update_access_token_from_refresh(request):
    """
    Updates OAuth access token using the refresh token.
    
    Request:
        POST request authenticated with JWT.
    
    Response:
        Returns JSON with new OAuth access token.
    """
    try:
        # Retrieve the refresh token from the JWT access token
        refresh_token = RefreshToken.objects.get(user_id=request.user.id).token
        
        # Check if refresh token is present
        if not refresh_token:
            raise Exception("Refresh token not found")

        # Query the OAuth access token object from the OAuth refresh token
        access_token_obj = AccessToken.objects.get(pk=(RefreshToken.objects.get(token=refresh_token)).access_token_id)

        # Create a new OAuth access token
        new_access_token = generate_base64_string()

        # Set the expiration time for the new OAuth access token
        expires_in = timezone.now() + timezone.timedelta(seconds=settings.OAUTH2_PROVIDER['ACCESS_TOKEN_EXPIRE_SECONDS'])
        access_token_obj.token = new_access_token
        expires_iso = expires_in.isoformat()

        # Assign the new OAuth access token and save it
        access_token_obj.expires = expires_iso
        access_token_obj.save()

        return JsonResponse(
            {
                "status": "Success",
                "message": "New access token has been issued",
                "token": new_access_token
            }
        )

    except Exception as ex:
        return JsonResponse({
            "status": "failed",
            "message": str(ex)
        })

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def calling_dummy_api_in_another_project(request):
    """
    Calls a dummy API in another project using OAuth access token.
    
    Request:
        POST request authenticated with JWT containing data for the API call.
    
    Response:
        Returns JSON response from the called API.
    """
    try:
        # Extract data from the request body
        data = json.loads(request.body)
        url = data.get('url')
        num = data.get('data')
        
        # Get the OAuth access token
        access_token = AccessToken.objects.get(user_id=request.user.id).token

        # Check if the access token has expired
        if timezone.now() > AccessToken.objects.get(user_id=request.user.id).expires:
            # Prepare headers for the request with the expired access token
            headers = {
                'Authorization': f'Bearer {str(request.auth)}',
                'Content-Type': 'application/json'
            }

            # Call the API to update the access token
            calling_update_access_token_api = requests.post("http://127.0.0.1:8001/api/update-access-token/", headers=headers)
            
            # Get the newly generated access token
            newly_generated_access_token = calling_update_access_token_api.json()['token']

            # Prepare headers for the request with the new access token
            headers = {
                'Authorization': f'Bearer {newly_generated_access_token}',
                'Content-Type': 'application/json'
            }

            # Prepare the data for the request
            post_data = {'data': num}
            post_data_json = json.dumps(post_data)

            # Make the API call to the 3rd party endpoint
            calling_inbuilt_3rdparty_api = requests.post("http://127.0.0.1:8001/api/call-3rd-party/", headers=headers, data=post_data_json)

            # Return the response from the 3rd party API
            return JsonResponse(calling_inbuilt_3rdparty_api.json())

        else:
            # Prepare headers for the request with the existing access token
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }

            # Prepare the data for the request
            post_data = {'data': num}
            post_data_json = json.dumps(post_data)

            # Make the API call to the 3rd party endpoint
            calling_inbuilt_3rdparty_api = requests.post("http://127.0.0.1:8001/api/call-3rd-party/", headers=headers, data=post_data_json)

            # Return the response from the 3rd party API
            return JsonResponse(calling_inbuilt_3rdparty_api.json())

    except Exception as ex:
        # Handle exceptions and return an error response
        return JsonResponse({
            "status": "failed",
            "message": str(ex)
        })


@csrf_exempt
@protected_resource()
def calling_3rd_party(request):
    """
    Calls a 3rd party API endpoint.
    
    Request:
        POST request containing data for the API call.
    
    Response:
        Returns JSON response from the 3rd party API.
    """
    try:
        # Extract data from the request body
        data = json.loads(request.body)
        post_data_json = json.dumps(data)

        # Make a POST request to the 3rd party API
        calling_project2 = requests.post("http://127.0.0.1:8000/api/dummyApi/", data=post_data_json)

        # Get the response data from the 3rd party API
        response_data = calling_project2.json()

        # Prepare and return the JsonResponse with the response data
        return JsonResponse(
            {
                "status": response_data['status'],
                "message": response_data['message']
            }
        )

    except Exception as ex:
        # Handle exceptions and return an error response
        return JsonResponse({
            "status": "failed",
            "message": str(ex)
        })

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_aws_details(request):
    """
    Retrieves AWS details including IAM users and EC2 instances.
    
    Request:
        GET request authenticated with JWT.
    
    Response:
        Returns JSON response with IAM users and EC2 instances details.
    """


    # Retrieve AWS credentials from environment variables
    aws_access_key_id = settings.AWS_ACCESS_KEY_ID
    aws_secret_access_key = settings.AWS_SECRET_ACCESS_KEY

    # Initialize AWS clients
    iam = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    ec2 = boto3.client('ec2', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name='ap-south-1')

    # Get IAM users
    users_response = iam.list_users()
    iam_users = {user['UserName']: user for user in users_response['Users']}

    # Get EC2 instances
    instances_response = ec2.describe_instances()
    ec2_instances_by_iam_user = {}

    for reservation in instances_response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_type = instance['InstanceType']
            state = instance['State']['Name']

            # Get IAM user tag from instance
            iam_user_tag = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'IAMUser'), None)

            # Create a list for the IAM user if not exists
            if iam_user_tag not in ec2_instances_by_iam_user:
                ec2_instances_by_iam_user[iam_user_tag] = []

            ec2_instances_by_iam_user[iam_user_tag].append({
                'instance_id': instance_id,
                'instance_type': instance_type,
                'state': state,
                # Add more instance details as needed
            })

    # Combine IAM users and EC2 instances data
    aws_details = {
        'iam_users': iam_users,
        'ec2_instances_by_iam_user': ec2_instances_by_iam_user,
    }

    return JsonResponse(aws_details, safe=False)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def add_iam_users(request):

    """
    Adds IAM users to the system and saves their credentials.
    
    Request:
        POST request authenticated with JWT containing IAM user data.
    
    Response:
        Returns JSON response indicating success or failure.
    """

    try:
        # Get the authenticated user making the request
        added_by_user = request.user

        # Parse the JSON data from the request body
        data = json.loads(request.body.decode('utf-8'))

        # Create IAMUser instances
        iam_users = []
        for iam_user_id, password in data['users'].items():
            iam_user = IAMUser.objects.create(
                iam_user_id=iam_user_id,
                password=password,
                added_by=added_by_user
            )
            iam_users.append({'iam_user_id': iam_user.iam_user_id,'password': iam_user.password,'added_by': [iam_user.added_by.id, iam_user.added_by.email] })


        access_token = AccessToken.objects.get(user_id=request.user.id).token

        # Check if the access token has expired
        if timezone.now() > AccessToken.objects.get(user_id=request.user.id).expires:
            # Prepare headers for the request with the expired access token
            headers = {
                'Authorization': f'Bearer {str(request.auth)}',
                'Content-Type': 'application/json'
            }

            # Call the API to update the access token
            calling_update_access_token_api = requests.post("http://127.0.0.1:8001/api/update-access-token/", headers=headers)
            
            # Get the newly generated access token
            newly_generated_access_token = calling_update_access_token_api.json()['token']

            headers = {
                'Authorization': f'Bearer {newly_generated_access_token}',
                'Content-Type': 'application/json'
            }

            # Prepare the data for the request
            post_data = {'data': iam_users}
            post_data_json = json.dumps(post_data)

            calling_inbuilt_3rdparty_api = requests.post("http://127.0.0.1:8001/api/save-iam-credentials/", headers=headers, data=post_data_json)

            return JsonResponse(
                {
                    "status":"Success",
                    "message":"IAM users data saved on both DB"
                }
            )
        
        else:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }

            # Prepare the data for the request
            post_data = {'data': iam_users}
            post_data_json = json.dumps(post_data)

            calling_inbuilt_3rdparty_api = requests.post("http://127.0.0.1:8001/api/save-iam-credentials/", headers=headers, data=post_data_json)

            return JsonResponse(
            {
                "message":"data saved on both dbs"
            }
        )
            

        return JsonResponse({'iam_users': iam_users})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
    

@csrf_exempt
@protected_resource()
def saving_iam_on_clinet(request):

    """
    Saves IAM user data on the client side.
    
    Request:
        POST request containing IAM user data.
    
    Response:
        Returns JSON response indicating success or failure.
    """
    

    try:
        # Extract data from the request body
        
        data = (json.loads(request.body)).get('data')
        post_data_json = json.dumps(data)

        # Make a POST request to the 3rd party API
        calling_project2 = requests.post("http://127.0.0.1:8000/api/save-iam-credentials/", data=post_data_json)

        # Get the response data from the 3rd party API
        response_data = calling_project2.json()

        # Prepare and return the JsonResponse with the response data
        return JsonResponse(
            {
                "message": response_data['message']
            }
        )

    except Exception as ex:
        # Handle exceptions and return an error response
        return JsonResponse({
            "status": "failed",
            "message": str(ex)
        })


