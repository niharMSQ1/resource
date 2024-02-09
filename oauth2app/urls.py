from django.urls import path
from .views import (
    user_registration,
    user_login,
    generate_token_endpoint,
    update_access_token_from_refresh,
    calling_dummy_api_in_another_project,
    calling_3rd_party,
    get_aws_details,
    add_iam_users,
    saving_iam_on_clinet,
)

urlpatterns = [
    path('user/registration/', user_registration, name='user-registration'),
    path('user/login/', user_login, name='user-login'),
    path('api/generate-token/', generate_token_endpoint, name='generate-token-endpoint'),
    path('api/update-access-token/', update_access_token_from_refresh, name='update-access-token'),
    path('api/call-dummy-api/', calling_dummy_api_in_another_project, name='call-dummy-api'),
    path('api/call-3rd-party/', calling_3rd_party, name='call-3rd-party'),
    path('api/get-aws-details/', get_aws_details, name='get_aws_details'),
    path('api/add-iam-users/', add_iam_users, name='add_iam_users'),
    path('api/save-iam-credentials/', saving_iam_on_clinet, name='add_iam_users'),
]
