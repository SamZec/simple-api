# Simple API

Simple HTTP API for playing with `User` model with authentication, authorization and Oauth2 implementation.


## Files

### `models/`

- `base.py`: base of all models of the API - handle serialization to file
- `users.py`: user model
- `Role.py`: role model
- `SetRole.py`: set role model

### `api/v1`

- `app.py`: entry point of the API
- `views/index.py`: basic endpoints of the API: `/public-data`
- `views/users.py`: all users endpoints
- `views/oauth2.py: third party log in


## Setup

```
$ pip3 install -r requirements.txt
```


## Run

```
$ API_HOST=0.0.0.0 API_PORT=5000 python3 -m api.v1.app
```


## Routes

- `POST /auth/register`: Register a new user.
- `POST /auth/login`: Authenticate a user and return a JWT.
- `POST /auth/assign-role`: Assign a role to a user (admin-only).
- `GET /profile`: Retrieve the authenticated user’s profile (accessible to authenticated users).
- `PUT /profile`: Update the authenticated user’s profile (authenticated users only).
- `DELETE /user/:id`: Delete a user by ID (admin-only).
- `GET /public-data`: Retrieve data accessible to all users, including guests.
