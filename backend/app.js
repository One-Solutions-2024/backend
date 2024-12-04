// Import required modules
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
require("dotenv").config(); // Load environment variables

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "MY_SECRET_TOKEN";
const DEFAULT_USERNAME = "Ekambaram";
const DEFAULT_PASSWORD = "Ekam#95423";

// MongoDB connection
mongoose.connect("mongodb+srv://ekambaram:ekam95423@cluster0.fbstm.mongodb.net/Job-Notifications" || "mongodb://localhost:27017/jobDatabase", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => console.log("MongoDB connected successfully"));

// Define MongoDB Schemas
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
  viewers: { type: Number, default: 0 }, // New field to track viewers

});

const popupSchema = new mongoose.Schema({
  popup_heading: String,
  popup_text: String,
  image: String,
  popup_belowtext: String,
  popup_routing_link: String,
  created_at: { type: Date, default: Date.now },
});

// MongoDB Models
const Job = mongoose.model("Job", jobSchema);
const PopupContent = mongoose.model("PopupContent", popupSchema);

// Initialize Express app
const app = express();

// Middleware
app.use(express.json());
app.use(helmet());
app.use(morgan("combined"));
app.use(bodyParser.json());

// CORS Configuration
const allowedOrigins = ["https://onesolutions.onrender.com", "https://onesolutions-admin.onrender.com", "http://localhost:3000"];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  optionsSuccessStatus: 200,
  credentials: true,
}));

// Dynamic hostname for serving image URLs
const hostname = process.env.HOSTNAME || `http://localhost:${PORT}`;
const getImageURL = (filename) => `${hostname}/uploads/${filename}`;

// Static file serving for images with adjusted CORS and cross-origin resource policy
app.use("/uploads", (req, res, next) => {
  res.header("Cross-Origin-Resource-Policy", "cross-origin");
  res.header("Access-Control-Allow-Origin", "*");
  next();
}, express.static('uploads'));

// Ensure uploads directory exists
fs.mkdir("uploads", { recursive: true })
  .then(() => console.log("Uploads directory ensured"))
  .catch((err) => console.error("Failed to create uploads directory:", err));

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: "uploads",
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  }
});
const upload = multer({ storage: storage });

// Middleware for JWT Authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).send("Unauthorized: No token provided");
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send("Unauthorized: Invalid token");
    req.user = user;
    next();
  });
};

// Admin Authorization
const authorizeAdmin = (req, res, next) => {
  if (req.user && req.user.role === "admin") next();
  else res.status(403).send("Access denied: Admins only");
};

// Login route
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (username === DEFAULT_USERNAME && password === DEFAULT_PASSWORD) {
    const token = jwt.sign({ username, role: "admin" }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Login successful", token });
  } else {
    res.status(401).json({ error: "Invalid username or password" });
  }
});

// Job Routes
app.get("/api/jobs", async (req, res) => {
  try {
    const jobs = await Job.find().sort({ createdAt: -1 });
    jobs.forEach(job => {
      job.image = getImageURL(job.image); // Add image URL
    });

    res.json(jobs); // Includes viewers field
  } catch (err) {
    console.error("Error fetching jobs:", err.message);
    res.status(500).json({ error: "Failed to fetch jobs" });
  }
});

// Fetch job by company name and job URL
app.get("/api/jobs/company/:companyname/:url_string", async (req, res) => {
  const { companyname, url_string } = req.params;

  try {
    const job = await Job.findOne({
      companyname: companyname.toLowerCase(), // Case-insensitive search
      url_string: url_string.toLowerCase(),
    });

    if (job) {
      job.image = getImageURL(job.image); // Ensure proper image URL
      res.json(job);
    } else {
      res.status(404).json({ error: "Job not found" });
    }
  } catch (err) {
    console.error(`Error fetching job by company name and URL: ${err.message}`);
    res.status(500).json({ error: "Failed to fetch job" });
  }
});



app.post("/api/jobs/:id/view", async (req, res) => {
  const { id } = req.params;

  try {
    const job = await Job.findById(id);
    if (!job) return res.status(404).json({ error: "Job not found" });

    job.viewers += 1; // Increment viewers count
    await job.save();

    res.json({ message: "Job view count incremented", viewers: job.viewers });
  } catch (error) {
    console.error("Error incrementing job view count:", error.message);
    res.status(500).json({ error: "Failed to increment job view count" });
  }
});


app.post("/api/jobs", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { companyname, title, description, apply_link, url_string, salary, location, job_type, experience, batch, job_uploader } = req.body;
  const image = req.file ? req.file.filename : null;
  if (!image) return res.status(400).json({ error: "Image file is required" });

  try {
    const newJob = new Job({ companyname, title, description, apply_link, image, url_string, salary, location, job_type, experience, batch, job_uploader });
    await newJob.save();
    res.status(201).json({ message: "Job added successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to add job" });
  }
});

app.put("/api/jobs/:id", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { id } = req.params;
  const { companyname, title, description, apply_link, url_string, salary, location, job_type, experience, batch, job_uploader } = req.body;
  const newImage = req.file ? req.file.filename : null;

  try {
    const job = await Job.findById(id);
    if (!job) return res.status(404).json({ error: "Job not found" });

    if (newImage && job.image) await fs.unlink(path.join(__dirname, "uploads", job.image)).catch(err => console.error("Error deleting old image:", err));
    job.set({ companyname, title, description, apply_link, url_string, salary, location, job_type, experience, batch, job_uploader, image: newImage || job.image });
    await job.save();
    res.json({ message: "Job updated successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to update job" });
  }
});

app.delete("/api/jobs/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const job = await Job.findById(id);
    if (!job) return res.status(404).json({ error: "Job not found" });

    if (job.image) await fs.unlink(path.join(__dirname, "uploads", job.image)).catch(err => console.error("Error deleting image:", err));
    await job.deleteOne();
    res.json({ message: "Job deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete job" });
  }
});

// Popup Routes
app.get("/api/popup", async (req, res) => {
  try {
    const popup = await PopupContent.findOne().sort({ created_at: -1 });
    if (popup) {
      popup.image = getImageURL(popup.image);
      res.json({ popup });
    } else {
      res.status(404).json({ popup: null, message: "No popup content available" });
    }
  } catch (error) {
    res.status(500).json({ error: "Failed to retrieve popup content" });
  }
});

// Admin Panel: Get all popup content
app.get("/api/popup/adminpanel", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const popupContent = await PopupContent.find().sort({ created_at: -1 }); // Sorting by created_at descending
    res.json(popupContent);
  } catch (error) {
    console.error(`Error fetching all popup content: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve popup content" });
  }
});


app.post("/api/popup/adminpanel", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { popup_heading, popup_text, popup_belowtext, popup_routing_link } = req.body;
  const image = req.file ? req.file.filename : null;
  if (!image) return res.status(400).json({ error: "Image file is required" });

  try {
    const newPopup = new PopupContent({ popup_heading, popup_text, popup_belowtext, popup_routing_link, image });
    await newPopup.save();
    res.status(201).json({ message: "Popup content added successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to add popup content" });
  }
});

app.put("/api/popup/adminpanel/:id", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { id } = req.params;
  const { popup_heading, popup_text, popup_belowtext, popup_routing_link } = req.body;
  const newImage = req.file ? req.file.filename : null;

  try {
    const popup = await PopupContent.findById(id);
    if (!popup) return res.status(404).json({ error: "Popup content not found" });

    // If a new image is uploaded, delete the old one
    if (newImage && popup.image) {
      await fs.unlink(path.join(__dirname, "uploads", popup.image)).catch(err => console.error("Error deleting old image:", err));
    }

    popup.set({
      popup_heading,
      popup_text,
      popup_belowtext,
      popup_routing_link,
      image: newImage || popup.image,
    });

    await popup.save();
    res.json({ message: "Popup content updated successfully" });
  } catch (error) {
    console.error("Error updating popup content:", error.message);
    res.status(500).json({ error: "Failed to update popup content" });
  }
});
app.delete("/api/popup/adminpanel/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const popup = await PopupContent.findById(id);
    if (!popup) return res.status(404).json({ error: "Popup content not found" });

    // Delete the associated image if it exists
    if (popup.image) {
      await fs.unlink(path.join(__dirname, "uploads", popup.image)).catch(err => console.error("Error deleting image:", err));
    }

    await popup.deleteOne();
    res.json({ message: "Popup content deleted successfully" });
  } catch (error) {
    console.error("Error deleting popup content:", error.message);
    res.status(500).json({ error: "Failed to delete popup content" });
  }
});


// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}/`);
});
