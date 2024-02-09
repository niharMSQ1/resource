from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    pass

class IAMUser(models.Model):
    iam_user_id = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    added_by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.iam_user_id
