

// Import required modules
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
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

const pool = new Pool({
  user: "jobdatabase_hobn_user",
  host: "dpg-ct6ltatds78s73c58jh0-a",
  database: "jobdatabase_hobn",
  password: "MbZX1UnM4kj123mJdtctATfvAfDf9Qdt",
  port: 5432, // default PostgreSQL port
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Use this to bypass certificate verification
  },
  
});

// Initialize Express app
const app = express();

// Middleware
app.use(express.json());


app.use(helmet());
app.use(morgan("combined"));
app.use(bodyParser.json());
// CORS Configuration
const allowedOrigins = ["https://onesolutions.onrender.com"];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  optionsSuccessStatus: 200,
  credentials: true, // Include credentials if needed
}));

// Dynamic hostname for serving image URLs
const hostname = process.env.HOSTNAME || `https://backend-lt9m.onrender.com`;
const getImageURL = (filename) => `${hostname}/uploads/${filename}`;

// Static file serving for images with CORS headers
app.use("/uploads", cors(), express.static('uploads'));

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


// Middleware for rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

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

// Utility function to execute queries
const executeQuery = async (query, params = []) => {
  try {
    return await pool.query(query, params);
  } catch (error) {
    console.error("Database Query Error:", error.message);
    throw new Error("Database operation failed");
  }
};

// Login route
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (username === DEFAULT_USERNAME && password === DEFAULT_PASSWORD) {
    const token = jwt.sign({ username, role: "admin" }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Login successful", token });
  } else {
    res.status(401).json({ error: "Invalid username or password" });
  }
});

// Database initialization
const initializeDbAndServer = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS job (
        id SERIAL PRIMARY KEY,
        companyname TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        apply_link TEXT NOT NULL,
        image TEXT NOT NULL,
        url TEXT NOT NULL,
        salary TEXT NOT NULL,
        location TEXT NOT NULL,
        job_type TEXT NOT NULL,
        experience TEXT NOT NULL,
        batch TEXT NOT NULL,
        job_uploader TEXT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS popup_content (
        id SERIAL PRIMARY KEY,
        popup_heading TEXT NOT NULL,
        popup_text TEXT NOT NULL,
        image TEXT NOT NULL,
        popup_belowtext TEXT NOT NULL,
        popup_routing_link TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}/`);
    });
  } catch (error) {
    console.error("Error initializing database:", error.message);
    process.exit(1);
  }
};

// Routes for job entity
app.get("/api/jobs", async (req, res) => {
  try {
    const query = "SELECT * FROM job ORDER BY createdAt DESC";
    const { rows } = await pool.query(query);
    rows.forEach(job => {
      job.image = getImageURL(job.image);
    });
    res.json(rows);
  } catch (err) {
    console.error("Error fetching jobs:", err.message);
    res.status(500).json({ error: "Failed to fetch jobs" });
  }
});
// Admin Panel: Get all jobs (admin access only)
app.get("/api/jobs/adminpanel", authenticateToken, authorizeAdmin, async (req, res) => {
  const getAllJobsQuery = `SELECT * FROM job ORDER BY createdAt DESC;`;

  try {
    const jobsArray = await pool.query(getAllJobsQuery);
    res.send(jobsArray.rows);
  } catch (error) {
    console.error("Error retrieving jobs:", error);
    res.status(500).send("An error occurred while retrieving jobs.");
  }
});

app.post("/api/jobs", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { companyname, title, description, apply_link, url, salary, location, job_type, experience, batch, job_uploader } = req.body;
  const image = req.file ? req.file.filename : null;
  if (!image) return res.status(400).json({ error: "Image file is required" });

  try {
    const query = `
      INSERT INTO job (companyname, title, description, apply_link, image, url, salary, location, job_type, experience, batch, job_uploader)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);
    `;
    await executeQuery(query, [companyname, title, description, apply_link, image, url, salary, location, job_type, experience, batch, job_uploader]);
    res.status(201).json({ message: "Job added successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to add job" });
  }
});

app.put("/api/jobs/:id", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { id } = req.params;
  const { companyname, title, description, apply_link, url, salary, location, job_type, experience, batch, job_uploader } = req.body;
  const newImage = req.file ? req.file.filename : null;

  try {
    const existingJob = await executeQuery("SELECT * FROM job WHERE id = $1;", [id]);
    if (!existingJob.rows.length) return res.status(404).json({ error: "Job not found" });

    const oldImage = existingJob.rows[0].image;
    if (newImage && oldImage) await fs.unlink(path.join(__dirname, "uploads", oldImage)).catch(err => console.error("Error deleting old image:", err));

    const query = `
      UPDATE job
      SET companyname = $1, title = $2, description = $3, apply_link = $4, image = $5, url = $6, salary = $7, location = $8, job_type = $9, experience = $10, batch = $11, job_uploader = $12
      WHERE id = $13;
    `;
    await executeQuery(query, [companyname, title, description, apply_link, newImage || oldImage, url, salary, location, job_type, experience, batch, job_uploader, id]);
    res.json({ message: "Job updated successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to update job" });
  }
});

// Delete a job
app.delete("/api/jobs/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const job = await executeQuery("SELECT * FROM job WHERE id = $1;", [id]);
    if (!job.rows.length) return res.status(404).json({ error: "Job not found" });

    const imageToDelete = job.rows[0].image;
    if (imageToDelete) await fs.unlink(path.join(__dirname, "uploads", imageToDelete)).catch(err => console.error("Error deleting image:", err));

    await executeQuery("DELETE FROM job WHERE id = $1;", [id]);
    res.json({ message: "Job deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete job" });
  }
});

// Fetch job by company name and job URL
app.get('/api/jobs/company/:companyname/:url', async (req, res) => {
  const { companyname, url } = req.params;

  const getJobByCompanyNameQuery = `
    SELECT * FROM job WHERE LOWER(companyname) = LOWER($1) AND LOWER(url) = LOWER($2);
  `;

  try {
    const job = await pool.query(getJobByCompanyNameQuery, [companyname, url]);

    if (job.rows.length) {
      res.json(job.rows[0]);
    } else {
      res.status(404).json({ error: "Job not found" });
    }
  } catch (error) {
    console.error(`Error fetching job by company name and URL: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch job" });
  }
});

// Routes for popup_content entity (similar to jobs)
app.get("/api/popup", async (req, res) => {
  try {
    const popupResult = await pool.query("SELECT * FROM popup_content ORDER BY created_at DESC LIMIT 1;");
    const popup = popupResult.rows[0];
    if (popup) {
      res.json({ popup });
    } else {
      res.json({ popup: null });
    }
  } catch (error) {
    console.error(`Error fetching popup content: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve popup content" });
  }
});

// Admin Panel: Get all popup content
app.get("/api/popup/adminpanel", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const popupResult = await pool.query("SELECT * FROM popup_content ORDER BY created_at DESC;");
    res.json(popupResult.rows);
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
    const query = `
      INSERT INTO popup_content (popup_heading, popup_text, image, popup_belowtext, popup_routing_link)
      VALUES ($1, $2, $3, $4, $5);
    `;
    await executeQuery(query, [popup_heading, popup_text, image, popup_belowtext, popup_routing_link]);
    res.status(201).json({ message: "Popup content added successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to add popup content" });
  }
});

// Update popup_content by ID
app.put("/api/popup/adminpanel/:id", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { id } = req.params;
  const { popup_heading, popup_text, popup_belowtext, popup_routing_link } = req.body;
  const newImage = req.file ? req.file.filename : null;

  try {
    const existingPopup = await executeQuery("SELECT * FROM popup_content WHERE id = $1;", [id]);
    if (!existingPopup.rows.length) return res.status(404).json({ error: "Popup content not found" });

    const oldImage = existingPopup.rows[0].image;
    if (new Image && oldImage) await fs.unlink(path.join(__dirname, "uploads", oldImage)).catch(err => console.error("Error deleting old image:", err));

    const query = `
      UPDATE popup_content
      SET popup_heading = $1, popup_text = $2, popup_belowtext = $3, popup_routing_link = $4, image = $5
      WHERE id = $6;
    `;
    await executeQuery(query, [popup_heading, popup_text, popup_belowtext, popup_routing_link, newImage || oldImage, id]);
    res.json({ message: "Popup content updated successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to update popup content" });
  }
});

// Delete popup_content by ID
app.delete("/api/popup/adminpanel/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const popup = await executeQuery("SELECT * FROM popup_content WHERE id = $1;", [id]);
    if (!popup.rows.length) return res.status(404).json({ error: "Popup content not found" });

    const imageToDelete = popup.rows[0].image;
    if (imageToDelete) await fs.unlink(path.join(__dirname, "uploads", imageToDelete)).catch(err => console.error("Error deleting image:", err));

    await executeQuery("DELETE FROM popup_content WHERE id = $1;", [id]);
    res.json({ message: "Popup content deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete popup content" });
  }
});

// Start server
initializeDbAndServer();