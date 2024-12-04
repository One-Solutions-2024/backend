// Required Modules
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const fs = require("fs").promises;
const bodyParser = require("body-parser");
const path = require("path");
const multer = require("multer");
require("dotenv").config();

// Configuration
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "MY_SECRET_TOKEN";
const DEFAULT_USERNAME = "Ekambaram";
const DEFAULT_PASSWORD = "Ekam#95423";

// MongoDB Connection
mongoose.connect("mongodb+srv://ekambaram:ekam95423@cluster0.fbstm.mongodb.net/Job-Notifications" || "mongodb://localhost:27017/jobDatabase", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => console.log("MongoDB connected successfully"));

// MongoDB Schemas
const jobSchema = new mongoose.Schema({
  companyname: String,
  title: String,
  description: String,
  apply_link: String,
  image: String,
  url_string: String,
  salary: String,
  location: String,
  job_type: String,
  experience: String,
  batch: String,
  job_uploader: String,
  createdAt: { type: Date, default: Date.now },
  viewers: { type: Number, default: 0 },
});

const popupSchema = new mongoose.Schema({
  popup_heading: String,
  popup_text: String,
  image: String,
  popup_belowtext: String,
  popup_routing_link: String,
  created_at: { type: Date, default: Date.now },
});

// Models
const Job = mongoose.model("Job", jobSchema);
const PopupContent = mongoose.model("PopupContent", popupSchema);

// Express App
const app = express();
app.use(express.json());
app.use(helmet());
app.use(morgan("combined"));
app.use(bodyParser.json());

// CORS Setup
const allowedOrigins = [
  "https://onesolutions.onrender.com",
  "https://onesolutions-admin.onrender.com",
  "http://localhost:3000",
];
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    optionsSuccessStatus: 200,
    credentials: true,
  })
);

// Dynamic Image Hostname
const hostname = process.env.HOSTNAME || `http://localhost:${PORT}`;
const getImageURL = (filename) => `${hostname}/uploads/${filename}`;

// Static Files and Ensure Uploads Directory
app.use(
  "/uploads",
  (req, res, next) => {
    res.header("Cross-Origin-Resource-Policy", "cross-origin");
    res.header("Access-Control-Allow-Origin", "*");
    next();
  },
  express.static("uploads")
);
fs.mkdir("uploads", { recursive: true }).catch((err) => console.error("Failed to create uploads directory:", err));

// Multer Setup
const storage = multer.diskStorage({
  destination: "uploads",
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  },
});
const upload = multer({ storage: storage });

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized: No token provided" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Unauthorized: Invalid token" });
    req.user = user;
    next();
  });
};

// Admin Authorization Middleware
const authorizeAdmin = (req, res, next) => {
  if (req.user && req.user.role === "admin") next();
  else res.status(403).json({ error: "Access denied: Admins only" });
};

// Login Route
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (username === DEFAULT_USERNAME && password === DEFAULT_PASSWORD) {
    const token = jwt.sign({ username, role: "admin" }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Login successful", token });
  } else {
    res.status(401).json({ error: "Invalid username or password" });
  }
});

// Jobs API

// Get All Jobs
app.get("/api/jobs", async (req, res) => {
  try {
    const jobs = await Job.find().sort({ createdAt: -1 });
    const jobsWithImages = jobs.map((job) => ({ ...job.toObject(), image: getImageURL(job.image) }));
    res.json(jobsWithImages);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch jobs" });
  }
});

// Get Job by Company and URL String
app.get("/api/jobs/company/:companyname/:url_string", async (req, res) => {
  const { companyname, url_string } = req.params;
  try {
    const job = await Job.findOne({
      companyname: { $regex: new RegExp(`^${companyname}$`, "i") }, // Case-insensitive match
      url_string: { $regex: new RegExp(`^${url_string}$`, "i") },  // Case-insensitive match
    });
    if (!job) return res.status(404).json({ error: "Job not found" });

    res.json({ ...job.toObject(), image: getImageURL(job.image) });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch job" });
  }
});

// Increment Viewers Count
app.post("/api/jobs/:id/view", async (req, res) => {
  const { id } = req.params;
  if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ error: "Invalid ID" });

  try {
    const job = await Job.findById(id);
    if (!job) return res.status(404).json({ error: "Job not found" });

    job.viewers += 1;
    await job.save();
    res.json({ message: "View count updated", viewers: job.viewers });
  } catch (err) {
    res.status(500).json({ error: "Failed to update view count" });
  }
});

// Add New Job
app.post("/api/jobs", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { companyname, title, description, apply_link, url_string, salary, location, job_type, experience, batch, job_uploader } = req.body;
  if (!req.file) return res.status(400).json({ error: "Image file is required" });

  const jobData = {
    companyname,
    title,
    description,
    apply_link,
    url_string,
    salary,
    location,
    job_type,
    experience,
    batch,
    job_uploader,
    image: req.file.filename,
  };

  try {
    const newJob = new Job(jobData);
    await newJob.save();
    res.status(201).json({ message: "Job added successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to add job" });
  }
});

// Update Job
app.put("/api/jobs/:id", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { id } = req.params;
  if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ error: "Invalid ID" });

  const { companyname, title, description, apply_link, url_string, salary, location, job_type, experience, batch, job_uploader } = req.body;

  try {
    const job = await Job.findById(id);
    if (!job) return res.status(404).json({ error: "Job not found" });

    if (req.file) {
      if (job.image) await fs.unlink(path.join(__dirname, "uploads", job.image));
      job.image = req.file.filename;
    }

    Object.assign(job, { companyname, title, description, apply_link, url_string, salary, location, job_type, experience, batch, job_uploader });
    await job.save();

    res.json({ message: "Job updated successfully", updated: job });
  } catch (err) {
    res.status(500).json({ error: "Failed to update job" });
  }
});

// Delete Job
app.delete("/api/jobs/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ error: "Invalid ID" });

  try {
    const job = await Job.findById(id);
    if (!job) return res.status(404).json({ error: "Job not found" });

    if (job.image) await fs.unlink(path.join(__dirname, "uploads", job.image));
    await Job.deleteOne({ _id: id });

    res.json({ message: "Job deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete job" });
  }
});

// Get all Popup Content
app.get("/api/popup", async (req, res) => {
  try {
    const content = await PopupContent.find().sort({ created_at: -1 });
    res.json(content);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch popup content" });
  }
});

// Add New Popup Content
app.post("/api/popup", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { popup_heading, popup_text, popup_belowtext, popup_routing_link } = req.body;
  if (!req.file) return res.status(400).json({ error: "Image file is required" });

  const popupData = {
    popup_heading,
    popup_text,
    popup_belowtext,
    popup_routing_link,
    image: req.file.filename,
  };

  try {
    const newPopup = new PopupContent(popupData);
    await newPopup.save();
    res.status(201).json({ message: "Popup content added successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to add popup content" });
  }
});

// Update Popup Content
app.put("/api/popup/:id", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { id } = req.params;
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Invalid ID" });
  }

  const { popup_heading, popup_text, popup_belowtext, popup_routing_link } = req.body;

  try {
    const popup = await PopupContent.findById(id);
    if (!popup) {
      return res.status(404).json({ error: "Popup content not found" });
    }

    // Replace the image if a new one is provided
    if (req.file) {
      if (popup.image) {
        await fs.unlink(path.join(__dirname, "uploads", popup.image));
      }
      popup.image = req.file.filename;
    }

    // Update fields
    if (popup_heading) popup.popup_heading = popup_heading;
    if (popup_text) popup.popup_text = popup_text;
    if (popup_belowtext) popup.popup_belowtext = popup_belowtext;
    if (popup_routing_link) popup.popup_routing_link = popup_routing_link;

    await popup.save();
    res.json({ message: "Popup content updated successfully", updated: popup });
  } catch (err) {
    res.status(500).json({ error: "Failed to update popup content" });
  }
});

// Delete Popup Content
app.delete("/api/popup/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ error: "Invalid ID" });

  try {
    const popup = await PopupContent.findById(id);
    if (!popup) return res.status(404).json({ error: "Popup content not found" });

    if (popup.image) await fs.unlink(path.join(__dirname, "uploads", popup.image));
    await PopupContent.deleteOne({ _id: id });

    res.json({ message: "Popup content deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete popup content" });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
