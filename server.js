const express = require("express");
const mongoose = require("mongoose");
const User = require("./models/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();

const app = express();
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// JWT Secret from env
const JWT_SECRET = process.env.JWT_SECRET;

// Register
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ message: "User already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ email, password: hashedPassword });
  await user.save();

  res.json({ message: "User registered successfully ✅" });
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ message: "Invalid credentials ❌" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ message: "Invalid credentials ❌" });

  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ message: "Login successful ✅", token });
});

// Middleware
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Access denied. No token provided." });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
}

// Profile
app.get("/profile", verifyToken, async (req, res) => {
  const user = await User.findById(req.user.userId).select("-password");
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json(user);
});

// Update user
app.put("/update-user", verifyToken, async (req, res) => {
  const { email, password } = req.body;
  const updates = {};

  if (email) updates.email = email;
  if (password) updates.password = await bcrypt.hash(password, 10);

  const user = await User.findByIdAndUpdate(req.user.userId, updates, { new: true });
  res.json({ message: "User updated ✅", user });
});

// Delete account
app.delete("/delete-account", verifyToken, async (req, res) => {
  await User.findByIdAndDelete(req.user.userId);
  res.json({ message: "User deleted successfully ❌" });
});

// Logout
app.post("/logout", (req, res) => {
  res.json({ message: "Logout successful (client should delete token)" });
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
