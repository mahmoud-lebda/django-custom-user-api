# Django Custom User API

The Django’s built-in authentication system is great but to build a real-world project, the official [Django documentation](https://docs.djangoproject.com/en/4.1/topics/auth/customizing/) highly recommends using a custom user model instead. Commonly we want to store a few more data related to our User and authenticate using social media.
it's recommended to always use a custom user model for all new Django projects even if you don't need to add any custom user fields in the beginning.

this project is an example for build custom user model api

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

