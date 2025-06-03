# Complaint Management System

A web-based complaint management system with user authentication and separate dashboards for users and administrators.

## Features

- User Authentication (Login/Signup)
- User Dashboard
  - Submit new complaints
  - View submitted complaints
  - Track complaint status
- Admin Dashboard
  - View all complaints
  - Manage complaint status
  - Filter complaints by status

## Prerequisites

- Node.js (v14 or higher)
- MongoDB (v4.4 or higher)
- npm (Node Package Manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd complaint-management-system
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory with the following content:
```
PORT=3000
MONGODB_URI=mongodb://localhost:27017/complaint-system
JWT_SECRET=your-secret-key
```

4. Start MongoDB service on your system

5. Run the application:
```bash
# Development mode
npm run dev

# Production mode
npm start
```

## Usage

1. Access the application at `http://localhost:3000`
2. Register a new account or login with existing credentials
3. Users will be redirected to the user dashboard
4. Admins will be redirected to the admin dashboard

## Default Admin Account

To create an admin account, you'll need to manually update the user's role in the MongoDB database:

```javascript
db.users.updateOne(
  { email: "admin@example.com" },
  { $set: { role: "admin" } }
)
```

## API Endpoints

- POST `/api/register` - Register new user
- POST `/api/login` - User login
- GET `/api/logout` - User logout
- GET `/api/user-dashboard` - Access user dashboard
- GET `/api/admin-dashboard` - Access admin dashboard

## Security Features

- Password hashing using bcrypt
- JWT-based authentication
- HTTP-only cookies for token storage
- Role-based access control

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request 