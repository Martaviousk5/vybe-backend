# Vybe Backend API

The backend API for Vybe social media platform built with Node.js, Express, and MongoDB.

## 🚀 Features

- User authentication (JWT)
- Post creation and interaction
- Real-time messaging (Socket.io)
- Stories (24-hour content)
- Follow system
- Notifications
- Search functionality
- User profiles

## 📋 Prerequisites

- Node.js 14+ 
- MongoDB Atlas account
- npm or yarn

## 🛠️ Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/vybe-backend.git
cd vybe-backend
```

2. Install dependencies:
```bash
npm install
```

3. Create `.env` file:
```bash
cp .env.example .env
```

4. Update `.env` with your credentials:
```
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key
```

5. Start the server:
```bash
npm start
```

## 📚 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user

### Posts
- `GET /api/posts` - Get all public posts
- `GET /api/posts/feed` - Get personalized feed (auth required)
- `POST /api/posts` - Create new post (auth required)
- `POST /api/posts/:id/like` - Like/unlike post (auth required)
- `POST /api/posts/:id/comment` - Add comment (auth required)

### Users
- `GET /api/users/:username` - Get user profile
- `PUT /api/users/profile` - Update profile (auth required)
- `POST /api/users/:id/follow` - Follow/unfollow user (auth required)

### Stories
- `GET /api/stories` - Get stories from following (auth required)
- `POST /api/stories` - Create story (auth required)

### Messages
- `GET /api/messages/:userId` - Get conversation (auth required)
- `POST /api/messages` - Send message (auth required)

### Notifications
- `GET /api/notifications` - Get notifications (auth required)
- `PUT /api/notifications/read` - Mark as read (auth required)

### Search
- `GET /api/search/users?q=query` - Search users
- `GET /api/search/posts?q=query` - Search posts

## 🔐 Authentication

Include JWT token in Authorization header:
```
Authorization: Bearer your_jwt_token
```

## 🚀 Deployment

### Deploy to Render:
1. Push code to GitHub
2. Connect GitHub repo to Render
3. Add environment variables
4. Deploy!

### Deploy to Heroku:
```bash
heroku create your-app-name
heroku config:set MONGO_URI=your_connection_string
heroku config:set JWT_SECRET=your_secret
git push heroku main
```

## 📝 License

MIT License