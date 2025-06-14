const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads')); // Serve uploaded files

// Configure multer for image upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    // Accept only image files
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Not an image! Please upload an image.'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/complaint-system', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

const User = mongoose.model('User', userSchema);

// Complaint Schema
const complaintSchema = new mongoose.Schema({
    subject: { type: String, required: true },
    description: { type: String, required: true },
    category: { type: String, required: true, enum: ['Technical', 'Billing', 'Service', 'Product', 'Other'] },
    image: { type: String },
    status: { type: String, enum: ['pending', 'resolved'], default: 'pending' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    username: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    replies: [{
        message: { type: String, required: true },
        adminName: { type: String, required: true },
        createdAt: { type: Date, default: Date.now }
    }]
});

const Complaint = mongoose.model('Complaint', complaintSchema);

// Authentication Middleware
const authenticateUser = async (req, res, next) => {
    try {
        const token = req.cookies.token;
        if (!token) {
            return res.status(401).json({ message: 'Authentication required' });
        }

        const decoded = jwt.verify(token, 'your-secret-key');
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const user = new User({
            username,
            email,
            password: hashedPassword
        });

        await user.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Create token
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            'your-secret-key',
            { expiresIn: '24h' }
        );

        // Set cookie
        res.cookie('token', token, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        res.json({
            message: 'Login successful',
            role: user.role
        });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in' });
    }
});

app.get('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out successfully' });
});

// Complaint Routes
app.post('/api/complaints', authenticateUser, upload.single('image'), async (req, res) => {
    try {
        const { subject, description, category } = req.body;
        const complaint = new Complaint({
            subject,
            description,
            category,
            image: req.file ? req.file.filename : null,
            userId: req.user._id,
            username: req.user.username
        });
        await complaint.save();
        res.status(201).json(complaint);
    } catch (error) {
        console.error('Error submitting complaint:', error);
        res.status(500).json({ message: 'Error submitting complaint' });
    }
});

// Get user's complaints
app.get('/api/user/complaints', authenticateUser, async (req, res) => {
    try {
        const complaints = await Complaint.find({ userId: req.user._id }).sort({ createdAt: -1 });
        res.json(complaints);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching complaints' });
    }
});

// Get all complaints (admin only)
app.get('/api/admin/complaints', authenticateUser, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        const complaints = await Complaint.find().sort({ createdAt: -1 });
        res.json(complaints);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching complaints' });
    }
});

// Get total users count (admin only)
app.get('/api/admin/users/count', authenticateUser, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        const totalUsers = await User.countDocuments({ role: 'user' });
        res.json({ count: totalUsers });
    } catch (error) {
        console.error('Error fetching user count:', error);
        res.status(500).json({ message: 'Error fetching user count' });
    }
});

// Update complaint status (admin only)
app.patch('/api/admin/complaints/:id', authenticateUser, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        const complaint = await Complaint.findByIdAndUpdate(
            req.params.id,
            { status: req.body.status },
            { new: true }
        );
        res.json(complaint);
    } catch (error) {
        res.status(500).json({ message: 'Error updating complaint' });
    }
});

// Add reply to complaint (admin only)
app.post('/api/admin/complaints/:id/reply', authenticateUser, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }

        const { message } = req.body;
        if (!message) {
            return res.status(400).json({ message: 'Reply message is required' });
        }

        const complaint = await Complaint.findById(req.params.id);
        if (!complaint) {
            return res.status(404).json({ message: 'Complaint not found' });
        }

        complaint.replies.push({
            message,
            adminName: req.user.username || 'Admin',
            createdAt: new Date()
        });

        await complaint.save();
        res.json(complaint);
    } catch (error) {
        console.error('Error adding reply:', error);
        res.status(500).json({ message: 'Error adding reply' });
    }
});

// Delete complaint (admin only)
app.delete('/api/admin/complaints/:id', authenticateUser, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        // First find the complaint to get the image filename
        const complaint = await Complaint.findById(req.params.id);
        if (!complaint) {
            return res.status(404).json({ message: 'Complaint not found' });
        }

        // If there's an image, delete it from the uploads folder
        if (complaint.image) {
            const imagePath = path.join(__dirname, 'uploads', complaint.image);
            try {
                fs.unlinkSync(imagePath);
            } catch (err) {
                console.error('Error deleting image file:', err);
                // Continue with complaint deletion even if image deletion fails
            }
        }

        // Delete the complaint from database
        await Complaint.findByIdAndDelete(req.params.id);
        res.json({ message: 'Complaint deleted successfully' });
    } catch (error) {
        console.error('Error deleting complaint:', error);
        res.status(500).json({ message: 'Error deleting complaint' });
    }
});

// Protected routes
app.get('/api/user-dashboard', authenticateUser, (req, res) => {
    if (req.user.role !== 'user') {
        return res.status(403).json({ message: 'Access denied' });
    }
    res.json({
        message: 'Welcome to user dashboard',
        name: req.user.username,
        email: req.user.email,
        role: req.user.role
    });
});

app.get('/api/admin-dashboard', authenticateUser, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    res.json({ message: 'Welcome to admin dashboard' });
});

// Serve static files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Catch-all route for client-side routing
app.get('*', (req, res, next) => {
    // If the request is for an API route, skip this middleware
    if (req.url.startsWith('/api/')) {
        return next();
    }
    
    // Check if the requested file exists in the public directory
    const filePath = path.join(__dirname, 'public', req.url);
    try {
        if (fs.existsSync(filePath)) {
            return res.sendFile(filePath);
        }
        // If file doesn't exist, send the index.html
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } catch (error) {
        next(error);
    }
});

// Error handling middleware for multer
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ message: 'File is too large. Maximum size is 5MB.' });
        }
        return res.status(400).json({ message: error.message });
    }
    next(error);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
}); 