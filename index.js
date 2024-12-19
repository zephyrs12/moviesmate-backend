const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const http =require("http");
const {Server}=require("socket.io");
const { Socket } = require("dgram");

const app = express();
const server=http.createServer(app);
const io=new Server(server);
const users = []; // In-memory users database (replace with a real database in production)
const SECRET_KEY = "your_secret_key";

// Middleware
const corsOptions = {
  origin:"https://moviesmate.onrender.com", // Frontend URL
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};
app.use(cors(corsOptions));
app.use(express.json());


// Token Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.header("Authorization");
  if (!authHeader) {
    return res.status(403).json({ error: "Access denied" });
  }

  const token = authHeader.replace("Bearer ", "").trim(); // Remove "Bearer " prefix
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }
      const storedUser = users.find((u) => u.email === user.email);
    if (!storedUser || !storedUser.tokens.includes(token)) {
      return res.status(403).json({ error: "Invalid or expired session" });
    }
    req.user = user;
    next();
  });
}

// Root Route
app.get("/", (req, res) => {
  res.send("Welcome to the MoviesMate Backend Server!");
});

// Signup API
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  // Validate input fields
  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters long" });
  }

  const userExists = users.find((user) => user.email === email);
  if (userExists) {
    return res.status(400).json({ error: "Email already registered" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ name, email, password: hashedPassword });
  res.status(201).json({ message: "User registered successfully" });
});

// Login API
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Validate input fields
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = users.find((user) => user.email === email);
  if (!user) {
    return res.status(400).json({ error: "Invalid email or password" });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ error: "Invalid email or password" });
  }

  const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "1h" });
  if (!user.tokens) user.tokens = []; // Ensure the tokens field exists
  user.tokens.push(token);
  console.log("Generated Token:", token);
  res.json({ message: "Login successful", token });
});

// Protected Profile API
app.get("/profile", authenticateToken, (req, res) => {
  const user = users.find((user) => user.email === req.user.email);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json({ name: user.name, email: user.email });
});
// Logout API

app.post("/logout", authenticateToken, (req, res) => {
    const user = users.find((u) => u.email === req.user.email);
    if (user) {
      user.tokens = user.tokens.filter((t) => t !== req.header("Authorization").replace("Bearer ", "").trim());
    }
    res.json({ message: "Logged out successfully" });
  });

//WebRTC Signalling Server logic
io.on("connection",(socket) =>{
    console.log("A user connected",socket.id);
    
//Handle WebRTC offer
socket.on("offer",(data) =>{
    console.log(`offer received from ${socket.id}to ${data.to}`);
    io.to(data.to).emit("offer",{
        from:socket.id,
        offer:data.offer,
    });
});
//Handle WebRTC answer
socket.on("offer", (data) => {
    console.log(`Offer received. From: ${socket.id}, To: ${data.to}`);
    console.log("Offer SDP:", data.offer);
    io.to(data.to).emit("offer", {
      from: socket.id,
      offer: data.offer,
    });
  });
socket.on("answer",(data) =>{
    console.log(`Answer received from ${socket.id}to ${data.to}`);
    io.to(data.to).emit("answer",{
        from:socket.id,
        answer:data.answer,
        });
    });
    //Handle WebRTC ICE candidate
    socket.on("ice-candidate",(data) =>{
        console.log(`ICE candidate from ${socket.id} to ${data.to}`);
        io.to(data.to).emit("ice-candidate",{
            from:socket.id,
            candidate:data.candidate,
            });
        });
    //handle disconnection
    socket.on("disconnect",() =>{
        console.log("User disconnected",socket.id);
        });
});

    

// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error("Error:", err.message);
  res.status(500).json({ error: "Something went wrong!" });
});

// Server Port
const PORT = 5002
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
