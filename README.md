# Auth Service (Spring Boot + JWT)

A secure authentication microservice built using Spring Boot and JWT.

---

## Features

- User Signup
- User Login
- JWT Authentication
- Refresh Token
- Logout
- Password Reset
- Account Lock after failed attempts
- Rate Limiting
- Audit Logging
- Role Based Access Control

---

## Tech Stack

- Java
- Spring Boot
- Spring Security
- JWT
- Redis
- MySQL
- Maven

---

## API Endpoints

### Authentication APIs

POST /auth/signup  
POST /auth/login  
POST /auth/refresh  
POST /auth/logout  

### Password APIs

POST /auth/forgot-password  
POST /auth/reset-password  

### Secure APIs

GET /api/me  

Authorization Header

Bearer <JWT_TOKEN>

### Admin APIs

GET /admin/users  
GET /admin/audit/logins  
GET /admin/users/{id}/status  
POST /admin/users/{id}/unlock  

---

## Authentication Flow

Client → Controller → Service → Repository → Database

---

## How to Run

git clone https://github.com/S1ddhar7h/auth-service3.git  
cd auth-service3  
mvn spring-boot:run
