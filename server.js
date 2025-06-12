const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIO = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://martaviouskency1:mNwiO3dymUcQE2yt@vybecluster.jzros5i.mongodb.net/?retryWrites=true&w=majority&appName=VybeCluster';
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected successfully'))
  .catch(err => console.log('❌ MongoDB connection error:', err));

// ===== MODELS =====

// User Model
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  fullName: { type: String, required: true },
  bio: { type: String, default: '' },
  avatar: { type: String },
  coverImage: { type: String },
  website: { type: String, default: '' },
  location: { type: String, default: '' },
  verified: { type: Boolean, default: false },
  vybeplus: {
    active: { type: Boolean, default: false },
    plan: { type: String, enum: ['monthly', 'annual', 'lifetime'], default: null },
    expiresAt: Date
  },
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  settings: {
    privateAccount: { type: Boolean, default: false },
    notifications: { type: Boolean, default: true },
    activityStatus: { type: Boolean, default: true }
  },
  lastActive: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

// Post Model
const PostSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true, maxlength: 2200 },
  images: [{ type: String }],
  hashtags: [{ type: String, lowercase: true }],
  mentions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: { type: String, required: true, maxlength: 500 },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
  }],
  shares: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  saves: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  visibility: { type: String, enum: ['public', 'followers', 'private'], default: 'public' },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

const Post = mongoose.model('Post', PostSchema);

// Story Model
const StorySchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: {
    type: { type: String, enum: ['image', 'video'], required: true },
    url: { type: String, required: true },
    text: String,
    textColor: String
  },
  viewers: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    viewedAt: { type: Date, default: Date.now }
  }],
  expiresAt: { type: Date, default: () => new Date(+new Date() + 24*60*60*1000) },
  createdAt: { type: Date, default: Date.now }
});

StorySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const Story = mongoose.model('Story', StorySchema);

// Message Model
const MessageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', MessageSchema);

// Notification Model
const NotificationSchema = new mongoose.Schema({
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['like', 'comment', 'follow', 'mention'], required: true },
  post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const Notification = mongoose.model('Notification', NotificationSchema);

// ===== MIDDLEWARE =====

// Auth Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error();
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key-change-this');
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) throw new Error();
    
    req.userId = decoded.userId;
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Please authenticate' });
  }
};

// ===== ROUTES =====

// Health Check
app.get('/', (req, res) => {
  res.json({ 
    message: '🎉 Vybe API is running!',
    version: '1.0.0',
    endpoints: {
      auth: {
        register: 'POST /api/auth/register',
        login: 'POST /api/auth/login'
      },
      posts: {
        create: 'POST /api/posts',
        getFeed: 'GET /api/posts/feed',
        like: 'POST /api/posts/:id/like',
        comment: 'POST /api/posts/:id/comment'
      },
      users: {
        profile: 'GET /api/users/:username',
        follow: 'POST /api/users/:id/follow',
        update: 'PUT /api/users/profile'
      },
      stories: {
        create: 'POST /api/stories',
        getAll: 'GET /api/stories'
      },
      messages: {
        send: 'POST /api/messages',
        getConversation: 'GET /api/messages/:userId'
      }
    }
  });
});

// ===== AUTH ROUTES =====

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, fullName } = req.body;
    
    // Validation
    if (!username || !email || !password || !fullName) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Check if user exists
    const exists = await User.findOne({ $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }] });
    if (exists) {
      return res.status(400).json({ 
        error: exists.email === email.toLowerCase() ? 'Email already registered' : 'Username already taken' 
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = new User({
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password: hashedPassword,
      fullName,
      avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${username}`
    });
    
    await user.save();
    
    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'your-secret-key-change-this');
    
    res.status(201).json({
      message: 'Account created successfully!',
      token,
      user: {
        id: user._id,
        username: user.username,
        fullName: user.fullName,
        email: user.email,
        avatar: user.avatar,
        verified: user.verified
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(400).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Find user
    const user = await User.findOne({
      $or: [
        { username: username.toLowerCase() }, 
        { email: username.toLowerCase() }
      ]
    });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last active
    user.lastActive = new Date();
    await user.save();
    
    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'your-secret-key-change-this');
    
    res.json({
      message: 'Login successful!',
      token,
      user: {
        id: user._id,
        username: user.username,
        fullName: user.fullName,
        email: user.email,
        avatar: user.avatar,
        bio: user.bio,
        verified: user.verified,
        vybeplus: user.vybeplus,
        followers: user.followers.length,
        following: user.following.length
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(400).json({ error: error.message });
  }
});

// ===== POST ROUTES =====

// Create Post
app.post('/api/posts', auth, async (req, res) => {
  try {
    const { content, images } = req.body;
    
    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: 'Content is required' });
    }
    
    // Extract hashtags
    const hashtags = content.match(/#\w+/g) || [];
    
    const post = new Post({
      author: req.userId,
      content: content.trim(),
      images: images || [],
      hashtags: hashtags.map(tag => tag.slice(1).toLowerCase())
    });
    
    await post.save();
    await post.populate('author', 'username fullName avatar verified');
    
    res.status(201).json({
      message: 'Post created successfully!',
      post
    });
  } catch (error) {
    console.error('Create post error:', error);
    res.status(400).json({ error: error.message });
  }
});

// Get Feed
app.get('/api/posts/feed', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const following = [...user.following, req.userId]; // Include own posts
    
    const posts = await Post.find({ author: { $in: following } })
      .populate('author', 'username fullName avatar verified')
      .populate('comments.user', 'username fullName avatar')
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json(posts);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get All Posts (Public)
app.get('/api/posts', async (req, res) => {
  try {
    const posts = await Post.find({ visibility: 'public' })
      .populate('author', 'username fullName avatar verified')
      .populate('comments.user', 'username fullName avatar')
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json(posts);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Like/Unlike Post
app.post('/api/posts/:postId/like', auth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    const likeIndex = post.likes.indexOf(req.userId);
    let liked = false;
    
    if (likeIndex > -1) {
      post.likes.splice(likeIndex, 1);
    } else {
      post.likes.push(req.userId);
      liked = true;
      
      // Create notification
      if (post.author.toString() !== req.userId) {
        await Notification.create({
          recipient: post.author,
          sender: req.userId,
          type: 'like',
          post: post._id
        });
      }
    }
    
    await post.save();
    res.json({ 
      message: liked ? 'Post liked' : 'Post unliked',
      likes: post.likes.length,
      liked
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Add Comment
app.post('/api/posts/:postId/comment', auth, async (req, res) => {
  try {
    const { text } = req.body;
    const post = await Post.findById(req.params.postId);
    
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    post.comments.push({
      user: req.userId,
      text: text.trim()
    });
    
    await post.save();
    
    // Create notification
    if (post.author.toString() !== req.userId) {
      await Notification.create({
        recipient: post.author,
        sender: req.userId,
        type: 'comment',
        post: post._id
      });
    }
    
    await post.populate('comments.user', 'username fullName avatar');
    
    res.json({
      message: 'Comment added',
      comments: post.comments
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ===== USER ROUTES =====

// Get User Profile
app.get('/api/users/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username.toLowerCase() })
      .select('-password -email')
      .populate('followers', 'username fullName avatar')
      .populate('following', 'username fullName avatar');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const posts = await Post.find({ author: user._id })
      .populate('author', 'username fullName avatar verified')
      .sort({ createdAt: -1 });
    
    res.json({
      user,
      posts,
      stats: {
        posts: posts.length,
        followers: user.followers.length,
        following: user.following.length
      }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Update Profile
app.put('/api/users/profile', auth, async (req, res) => {
  try {
    const updates = {};
    const allowedUpdates = ['fullName', 'bio', 'website', 'location', 'avatar', 'coverImage'];
    
    Object.keys(req.body).forEach(key => {
      if (allowedUpdates.includes(key)) {
        updates[key] = req.body[key];
      }
    });
    
    const user = await User.findByIdAndUpdate(
      req.userId,
      updates,
      { new: true, runValidators: true }
    ).select('-password');
    
    res.json({
      message: 'Profile updated successfully',
      user
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Follow/Unfollow User
app.post('/api/users/:userId/follow', auth, async (req, res) => {
  try {
    if (req.userId === req.params.userId) {
      return res.status(400).json({ error: 'You cannot follow yourself' });
    }
    
    const userToFollow = await User.findById(req.params.userId);
    const currentUser = await User.findById(req.userId);
    
    if (!userToFollow) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const isFollowing = currentUser.following.includes(userToFollow._id);
    
    if (isFollowing) {
      // Unfollow
      currentUser.following.pull(userToFollow._id);
      userToFollow.followers.pull(currentUser._id);
    } else {
      // Follow
      currentUser.following.push(userToFollow._id);
      userToFollow.followers.push(currentUser._id);
      
      // Create notification
      await Notification.create({
        recipient: userToFollow._id,
        sender: req.userId,
        type: 'follow'
      });
    }
    
    await currentUser.save();
    await userToFollow.save();
    
    res.json({ 
      message: isFollowing ? 'Unfollowed successfully' : 'Followed successfully',
      following: !isFollowing 
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ===== STORY ROUTES =====

// Create Story
app.post('/api/stories', auth, async (req, res) => {
  try {
    const { type, url, text, textColor } = req.body;
    
    const story = new Story({
      author: req.userId,
      content: { type, url, text, textColor }
    });
    
    await story.save();
    await story.populate('author', 'username fullName avatar');
    
    res.status(201).json({
      message: 'Story created successfully',
      story
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get Stories
app.get('/api/stories', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const following = [...user.following, req.userId];
    
    const stories = await Story.find({
      author: { $in: following },
      expiresAt: { $gt: new Date() }
    })
    .populate('author', 'username fullName avatar')
    .sort({ createdAt: -1 });
    
    res.json(stories);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ===== MESSAGE ROUTES =====

// Send Message
app.post('/api/messages', auth, async (req, res) => {
  try {
    const { recipientId, content } = req.body;
    
    const message = new Message({
      sender: req.userId,
      recipient: recipientId,
      content: content.trim()
    });
    
    await message.save();
    await message.populate('sender', 'username fullName avatar');
    await message.populate('recipient', 'username fullName avatar');
    
    // Emit socket event
    io.to(recipientId).emit('new_message', message);
    
    res.status(201).json({
      message: 'Message sent',
      data: message
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get Conversation
app.get('/api/messages/:userId', auth, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { sender: req.userId, recipient: req.params.userId },
        { sender: req.params.userId, recipient: req.userId }
      ]
    })
    .populate('sender', 'username fullName avatar')
    .populate('recipient', 'username fullName avatar')
    .sort({ createdAt: 1 });
    
    // Mark messages as read
    await Message.updateMany(
      { sender: req.params.userId, recipient: req.userId, read: false },
      { read: true }
    );
    
    res.json(messages);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ===== NOTIFICATION ROUTES =====

// Get Notifications
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const notifications = await Notification.find({ recipient: req.userId })
      .populate('sender', 'username fullName avatar')
      .populate('post', 'content')
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json(notifications);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Mark Notifications as Read
app.put('/api/notifications/read', auth, async (req, res) => {
  try {
    await Notification.updateMany(
      { recipient: req.userId, read: false },
      { read: true }
    );
    
    res.json({ message: 'Notifications marked as read' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ===== SEARCH ROUTES =====

// Search Users
app.get('/api/search/users', async (req, res) => {
  try {
    const { q } = req.query;
    if (!q) {
      return res.json([]);
    }
    
    const users = await User.find({
      $or: [
        { username: { $regex: q, $options: 'i' } },
        { fullName: { $regex: q, $options: 'i' } }
      ]
    })
    .select('username fullName avatar verified')
    .limit(20);
    
    res.json(users);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Search Posts
app.get('/api/search/posts', async (req, res) => {
  try {
    const { q } = req.query;
    if (!q) {
      return res.json([]);
    }
    
    const posts = await Post.find({
      $or: [
        { content: { $regex: q, $options: 'i' } },
        { hashtags: { $in: [q.toLowerCase().replace('#', '')] } }
      ]
    })
    .populate('author', 'username fullName avatar verified')
    .sort({ createdAt: -1 })
    .limit(50);
    
    res.json(posts);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ===== SOCKET.IO =====

const activeUsers = new Map();

io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  
  socket.on('user_online', (userId) => {
    activeUsers.set(userId, socket.id);
    socket.userId = userId;
    socket.join(userId);
    io.emit('user_status', { userId, status: 'online' });
  });
  
  socket.on('typing', ({ recipientId, typing }) => {
    io.to(recipientId).emit('user_typing', { userId: socket.userId, typing });
  });
  
  socket.on('disconnect', () => {
    if (socket.userId) {
      activeUsers.delete(socket.userId);
      io.emit('user_status', { userId: socket.userId, status: 'offline' });
    }
  });
});

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 Visit http://localhost:${PORT} to check if it's working`);
});