const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SECRET = "supersecretkey";

// MongoDB connection
mongoose.connect("mongodb://127.0.0.1:27017/expenseTracker")
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

  
// Schemas
const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String
});

const transactionSchema = new mongoose.Schema({
  username: String,
  email: String,
  text: String,
  amount: Number,
  category: String,
  createdAt: Date
});

const User = mongoose.model("User", userSchema);
const Transaction = mongoose.model("Transaction", transactionSchema);

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ message: "Missing fields" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashed });
    await user.save();

    res.json({ message: "Registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ username: user.username, email: user.email }, SECRET, { expiresIn: "2h" });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Auth middleware
function auth(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
}

// Add transaction
app.post("/api/transactions", auth, async (req, res) => {
  try {
    const { text, amount, category, createdAt } = req.body;
    if (!text || !amount) return res.status(400).json({ message: "Missing fields" });

    const tx = new Transaction({
      username: req.user.username,
      email: req.user.email,
      text,
      amount,
      category,
      createdAt: createdAt ? new Date(createdAt) : new Date()
    });

    await tx.save();
    res.json(tx);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to add transaction" });
  }
});

// Get transactions
app.get("/api/transactions", auth, async (req, res) => {
  try {
    const txs = await Transaction.find({ email: req.user.email });
    res.json(txs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch transactions" });
  }
});

// Delete transaction
app.delete("/api/transactions/:id", auth, async (req, res) => {
  try {
    await Transaction.deleteOne({ _id: req.params.id, email: req.user.email });
    res.json({ message: "Deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to delete transaction" });
  }
});

// Update transaction
app.put("/api/transactions/:id", auth, async (req, res) => {
  try {
    const { text, amount, category, createdAt } = req.body;
    const tx = await Transaction.findOne({ _id: req.params.id, email: req.user.email });
    if (!tx) return res.status(404).json({ message: "Transaction not found" });

    if (text !== undefined) tx.text = text;
    if (amount !== undefined) tx.amount = amount;
    if (category !== undefined) tx.category = category;
    if (createdAt !== undefined) tx.createdAt = new Date(createdAt);

    await tx.save();
    res.json(tx);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to update transaction" });
  }

});

app.listen(5000, () => console.log("Server running on http://localhost:5000"));