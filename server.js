const express = require("express");
const mongoose = require("mongoose");
const User = require("./models/User");
const jwt = require("jsonwebtoken");
const JWT_SECRET = "rahul_secret_123"; // In real-world, use env file
const bcrypt = require("bcrypt"); // ✅ Add this

const app = express();
app.use(express.json());


// Replace with your MongoDB URI
mongoose.connect("mongodb+srv://adsurerahul96:jrzlMLI9FyEvXace@cluster0.wuotla9.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0", {
//    useNewUrlParser: true,
//    useUnifiedTopology: true,
})
.then(() => console.log("✅ Connected to MongoDB Atlas"))
.catch(err => console.error("❌ MongoDB connection error:", err));


// ✅ Register Endpoint
app.post("/register", async (req, res) => {
    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return res.status(400).json({ message: "User already exists" });
    }

    const user = new User({ email, password });
    await user.save();

    res.json({ message: "User registered successfully ✅" });
});

// ✅ Login Endpoint
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (user) {
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
        res.json({ message: "Login successful ✅", token });
    } else {
        res.status(401).json({ message: "Invalid credentials ❌" });
    }
});

app.get("/profile", verifyToken, async (req, res) => {
    const user = await User.findById(req.user.userId).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
});

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

app.put("/update-user", verifyToken, async (req, res) => {
    const { email, password } = req.body;
    const updates = {};

    if (email) updates.email = email;
    if (password) {
        const hashed = await bcrypt.hash(password, 10);
        updates.password = hashed;
    }

    const user = await User.findByIdAndUpdate(req.user.userId, updates, { new: true });
    res.json({ message: "User updated ✅", user });
});
app.delete("/delete-account", verifyToken, async (req, res) => {
    await User.findByIdAndDelete(req.user.userId);
    res.json({ message: "User deleted successfully ❌" });
});

app.post("/logout", (req, res) => {
    res.json({ message: "Logout successful (client should delete token)" });
});

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
