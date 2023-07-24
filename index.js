const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();
const {
  User,
  Course,
  authenticateAdmin,
  authenticateUser,
  createJwtToken,
  createAdmin,
  createUser,
  verifyTokenAdmin,
  verifyTokenUser,
  updateCourse,
  getAllCourses,
  getACourse,
  adminRole,
  userRole
} = require('./utils');

const app = express();
app.use(express.json());

console.log({ connectionString: process.env.MONGODB_CONNECTION_STRING });
mongoose.connect(process.env.MONGODB_CONNECTION_STRING)

app.get('/', (req, res) => res.send('Home Page Route'));

// Admin signup
app.post('/admin/signup', (req, res) => {
  createAdmin(req, res);
});

// Admin login
app.post('/admin/login', authenticateAdmin, (req, res) => {
  const token = createJwtToken(req.headers.username, adminRole)
  return res.status(200).json({ message: 'Logged in successfully', token })
});

// Admin create course
app.post('/admin/courses', verifyTokenAdmin, async (req, res) => {
  const course = new Course(req.body);
  await course.save();
  return res.json({ message: 'Course created successfully', courseId: course.id })
});

// Admin edit/update course
app.put('/admin/courses/:courseId', verifyTokenAdmin, (req, res) => {
  updateCourse(req, res);
});

// Admin view all courses
app.get('/admin/courses', verifyTokenAdmin, (req, res) => {
  getAllCourses(res);
});

// User signup
app.post('/users/signup', (req, res) => {
  createUser(req, res);
});

// User login
app.post('/users/login', authenticateUser, (req, res) => {
  const token = createJwtToken(req.headers.username, userRole)
  return res.status(200).json({ message: 'Logged in successfully', token })
});

// User view all courses
app.get('/users/courses', verifyTokenUser, (req, res) => {
  getAllCourses(res);
});

// User purchase a course
app.post('/users/courses/:courseId', verifyTokenUser, async (req, res) => {
  const courseId = req.params.courseId;
  const course = await getACourse(courseId);
  if (!course) {
    return res.status(404).json({ message: 'Course not found' })
  }
  console.log({ course });

  const username = req.user.username;
  const user = await User.findOne({ username })
  if (!user) {
    return res.status(404).json({ message: 'User not found' })
  }
  const index = user.purchasedCourses.findIndex(id => id === courseId)
  if (index === -1) {
    return res.json({ message: 'Course already purchased' })
  }
  user.purchasedCourses.push(courseId)
  await user.save();
  return res.json({ message: 'Course purchased successfully' })
});

// User view purchased courses
app.get('/users/purchasedCourses', verifyTokenUser, async (req, res) => {
  const username = req.user.username;
  const user = await User.findOne({ username })
  if (!user) {
    return res.status(404).json({ message: 'User not found' })
  }
  return res.json({ purchasedCourses: user.purchasedCourses || [] })
});

// these two lines are important for Vercel deployment
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on ${port}, http://localhost:${port}`));
