const jwt = require('jsonwebtoken');
const fs = require('fs');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
require('dotenv').config();

const usersFilePath = './users.json';
const adminsFilePath = './admins.json';
const coursesFilePath = './courses.json';
const purchasedCourseFilePath = './purchasedCourses.json'
const jwtExpiresInSec = 3600;
const JWTSECRET = process.env.JWTSECRET;
const adminRole = 'admin';
const userRole = 'user';

// define mongoose schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    purchasedCourses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Course' }]
});

const adminSchema = mongoose.Schema({
    username: String,
    password: String
});

const courseSchema = mongoose.Schema({
    title: String,
    description: String,
    price: Number,
    imageLink: String,
    published: Boolean
});

// define mongoose model
const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Course = mongoose.model('Course', courseSchema);

/**
 * Middleware that Verifies the authenticity of the admin's JWT (JSON Web Token) in the request headers.
 * If the token is valid and the role is 'admin', it calls the next middleware.
 *
 * @param {object} req - The request object containing the authorization header with the JWT token.
 * @param {object} res - The response object used to send the response back to the client.
 * @param {function} next - The next middleware function to be called 
 * if the token is valid and the admin role is correct.
 * @returns {void}
 */
const verifyTokenAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: 'AuthHeaderNotFound' })
    }
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWTSECRET, (err, user) => {
        console.log({ verifyTokenAdmin: user })
        if (err) {
            return res.status(403).json({ message: 'Invalid/WrongToken' })
        } else if (user.role !== adminRole) {
            return res.status(403).json({ message: 'AccessForbidden' })
        }
        req.user = user;
        next();
    })
}

/**
 * Middleware that Authenticates the admin based on the provided username and password in the request headers.
 * If authentication is successful, it calls the next middleware.
 *
 * @param {object} req - The request object containing the username and password in the request headers.
 * @param {object} res - The response object used to send the response back to the client.
 * @param {function} next - The next middleware function to be called if authentication is successful.
 * @returns {void}
 */
const authenticateAdmin = async (req, res, next) => {
    const { username, password } = req.headers;
    const admin = await Admin.findOne({ username });
    console.log({ admin })
    if (!admin) {
        return res.status(403).json({ error: 'WrongUsername' })
    }
    bcrypt.compare(password, admin.password, (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'HashingError' })
        }
        if (result) {
            next();
        } else {
            return res.status(403).json({ message: 'WrongPassword' });
        }
    })
}

/**
 * Middleware that Authenticates the User based on the provided username and password in the request headers.
 * If authentication is successful, it calls the next middleware.
 *
 * @param {object} req - The request object containing the username and password in the request headers.
 * @param {object} res - The response object used to send the response back to the client.
 * @param {function} next - The next middleware function to be called if authentication is successful.
 * @returns {void}
 */
const authenticateUser = async (req, res, next) => {
    const { username, password } = req.headers;
    const user = await User.findOne({ username });
    console.log({ user })
    if (!user) {
        return res.status(403).json({ error: 'WrongUsername' })
    }
    bcrypt.compare(password, user.password, (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'HashingError' })
        }
        if (result) {
            next();
        } else {
            return res.status(403).json({ message: 'WrongPassword' });
        }
    })
}

/**
 * Creates a JWT (JSON Web Token) using the provided username and role.
 *
 * @param {string} username - The username to include in the JWT payload.
 * @param {string} role - The role to include in the JWT payload.
 * @returns {string} A JWT token representing the provided username and role.
 */
const createJwtToken = (username, role) => {
    const payload = { username, role };
    const token = jwt.sign(payload, JWTSECRET, {
        algorithm: "HS256",
        expiresIn: jwtExpiresInSec,
    })
    return token;
}

/**
 * Creates a new admin with the provided username and password.
 *
 * @param {object} req - The request object containing the admin's username and password in the request body.
 * @param {object} res - The response object used to send the response back to the client.
 * @returns {void}
 */
const createAdmin = async (req, res) => {
    const { username, password } = req.body;
    const salt = 10;
    const admin = await Admin.findOne({ username });
    console.log({ admin })
    if (admin) {
        return res.status(403).json({ message: 'Admin already exists' })
    }
    bcrypt.hash(password, salt, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: 'FailedToHashPassword' });
        }
        const newAdmin = new Admin({ username, password: hash })
        newAdmin.save()
        const token = createJwtToken(username, adminRole)
        return res.json({ message: 'Admin created successfully', token })
    })
}

/**
 * Creates a new user with the provided username and password.
 *
 * @param {object} req - The request object containing the user's username and password in the request body.
 * @param {object} res - The response object used to send the response back to the client.
 * @returns {void}
 */
const createUser = async (req, res) => {
    const { username, password } = req.body;
    const salt = 10;
    const user = await User.findOne({ username });
    console.log({ user })
    if (user) {
        return res.status(403).json({ message: 'User already exists' })
    }
    bcrypt.hash(password, salt, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: 'FailedToHashPassword' });
        }
        const newUser = new User({ username, password: hash })
        newUser.save()
        const token = createJwtToken(username, adminRole)
        return res.json({ message: 'User created successfully', token })
    })
}

/**
 * Middleware that Verifies the authenticity of the user's JWT (JSON Web Token) in the request headers.
 * If the token is valid and the role is 'user', it calls the next middleware.
 *
 * @param {object} req - The request object containing the authorization header with the JWT token.
 * @param {object} res - The response object used to send the response back to the client.
 * @param {function} next - The next middleware function to be called 
 * if the token is valid and the user role is correct.
 * @returns {void}
 */
const verifyTokenUser = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: 'AuthHeaderNotFound' })
    }
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWTSECRET, (err, user) => {
        console.log({ verifyTokenUser: user })
        if (err) {
            return res.status(403).json({ message: 'Invalid/WrongToken' })
        } else if (user.role !== userRole) {
            return res.status(403).json({ message: 'AccessForbidden' })
        }
        req.user = user;
        next();
    })
}

/**
 * Updates a course with the provided course ID using the data in the request body.
 *
 * @param {object} req - The request object containing the course ID in the URL parameters 
 * and the updated course data in the request body.
 * @param {object} res - The response object used to send the response back to the client.
 * @returns {void}
 */
const updateCourse = async (req, res) => {
    const courseId = req.params.courseId;
    console.log({ courseId })
    /*
    By default, when using findByIdAndUpdate(), 
    the method returns the original document before the update was applied. 
    However, by setting { new: true }, 
    you instruct the method to return the modified document instead.
    */
    try {
        const course = await Course.findByIdAndUpdate(courseId, req.body, { new: true });
        return res.json({ message: 'Course updated successfully' })
    } catch (error) {
        return res.status(404).json({ message: 'Course not found' })
    }
}

/**
 * Retrieves all the courses from the DB and sends them as a response.
 *
 * @param {object} res - The response object used to send the response back to the client.
 * @returns {void}
 */
const getAllCourses = async (res) => {
    const courses = await Course.find();
    if (courses === []) {
        return res.json({ message: 'No courses' })
    }
    return res.json({ courses })
}

/**
 * Retrieves a single course with the specified course ID.
 *
 * @param {number} courseId - The ID of the course to retrieve.
 * @returns {object|null} - The course object if found, or null if not found.
 */
const getACourse = async (courseId) => {
    try {
        const course = await Course.findById(courseId);
        return course
    } catch (error) {
        return null;
    }
}

module.exports = {
    User,
    Admin,
    Course,
    usersFilePath,
    adminsFilePath,
    coursesFilePath,
    purchasedCourseFilePath,
    adminRole,
    userRole,
    authenticateUser,
    authenticateAdmin,
    createJwtToken,
    verifyTokenAdmin,
    verifyTokenUser,
    updateCourse,
    getAllCourses,
    getACourse,
    createAdmin,
    createUser
}