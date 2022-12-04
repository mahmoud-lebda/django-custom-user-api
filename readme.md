# Building an API for Custom User Models with Django

Django is a Python framework that can be used for rapid web development. It has an API for user authentication, which is called django.contrib.auth and it's the default authentication system in Django.

Django allows developers to create their own custom user model and use it instead of the default one. This provides a way to customize the models of users and their permissions, as well as associate other models with them.

The official [Django documentation](https://docs.djangoproject.com/en/4.1/topics/auth/customizing/) recommend building a custom user model rather than using the built in Django User model. Usually, we want to store additional information and authenticate using social media.

it is advisable to use a custom user model from the beginning if you don't need any custom fields for user profiles in your project.

in this project we Building an API for Custom User Models

## Features

* Swagger
* well documented
* manualy build all api no third party


## API Endpoint

* Register New User API
* Email Verify API
* Token API
* Refresh token API
* User profile API
* Edit profile API

## Local development
To run this project in your development machine, follow these steps:


1. (optional) Create and activate a virtualenv:

windows

```
python -m venv env

env/scripts/activate
```

linux & macOS

```
python -m venv env

source .env/bin/activate
```

2. Fork this repo and clone your fork

3. Install dependencies:

```
pip install -r requirements.txt
```

4. Change .envexample to .env in core folder and add your environment settings

5. Create a development database:

```
python manage.py migrate
```

6. Create Super User:

```
python manage.py createsuperuser
```

7. If everything is alright, you should be able to start the Django development server:

```
python manage.py runserver
```

