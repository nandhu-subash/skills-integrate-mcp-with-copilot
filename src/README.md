# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Sign up for activities

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Run the application:

   ```
   python app.py
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                                 |
| ------ | ----------------------------------------------------------------- | --------------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count         |
| POST   | `/auth/login`                                                     | Log in with username/password to receive a bearer auth token               |
| GET    | `/auth/me`                                                        | Return the current authenticated user's profile                            |
| POST   | `/activities/{activity_name}/signup`                              | Sign up for an activity (requires bearer token; students sign themselves up, admins may provide `email=`) |
| DELETE | `/activities/{activity_name}/unregister`                          | Unregister from an activity (requires bearer token; students unregister themselves, admins may provide `email=`) |

## Authentication

The app now supports bearer token authentication with role-based access.

1. Send a POST request to `/auth/login` with form fields `username` and `password`.
2. Use the returned `access_token` in an `Authorization: Bearer <token>` header.
3. Students can call signup/unregister for themselves.
4. Admins can manage students by providing the student `email` query parameter.

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
