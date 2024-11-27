
// Import required modules
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const fs = require("fs").promises;
require("dotenv").config(); // Load environment variables

const bodyParser = require("body-parser");
const path = require("path");

const multer = require("multer")

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "MY_SECRET_TOKEN"; // JWT secret from environment variables

// Default admin credentials
const DEFAULT_USERNAME = "Ekambaram";
const DEFAULT_PASSWORD = "Ekam#95423";

// Initialize PostgreSQL pool using environment variable
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Initialize Express app
const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet()); // Basic security headers
app.use(morgan("combined")); // Logging

app.use(bodyParser.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
// Dynamic hostname for serving image URLs
const hostname = process.env.HOSTNAME || `http://localhost:${port}`;
const getImageURL = (filename) => `${hostname}/uploads/${filename}`;

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
      cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/gif"];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Invalid file type"), false);
    }
    
      cb(null, true);
  },
});

// Error handling for file uploads
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
      return res.status(400).json({ message: "File upload error", error: err.message });
  }
  next(err);
});

// Configure CORS for external access
const corsOptions = {
  origin: "*", // Replace "*" with specific domains for production
};
app.use(cors(corsOptions));


// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter); // Apply rate limiting to all routes

// JWT Authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).send("Unauthorized: No token provided");
  jwt.verify(token, JWT_SECRET, (error, user) => {
    if (error) return res.status(403).send("Unauthorized: Invalid token");
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
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (username === DEFAULT_USERNAME && password === DEFAULT_PASSWORD) {
    const token = jwt.sign({ username, role: "admin" }, JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ message: "Login successful", token });
  } else {
    res.status(401).json({ error: "Invalid username or password" });
  }
});


// Initialize DB and start server
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

    



    // Create popup_content table
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

     
    // Start server on 0.0.0.0 for external access
    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}/`);
    });


  } catch (error) {
    console.error(`Error initializing the database: ${error.message}`);
    process.exit(1);
  }
};
// Route to get all jobs with pagination
app.get("/api/jobs", async (req, res) => {
  const { page = 1, limit = 8 } = req.query;

  try {
    const offset = (page - 1) * parseInt(limit);
    const currentTime = new Date();
    const sevenDaysAgo = new Date(currentTime.setDate(currentTime.getDate() - 7));

    const getAllJobsQuery = `
      SELECT *, 
      CASE 
        WHEN createdAt >= $1 THEN 1 
        ELSE 0 
      END as isNew 
      FROM job 
      ORDER BY isNew DESC, createdAt DESC 
      LIMIT $2 OFFSET $3;
    `;

    const jobs = await pool.query(getAllJobsQuery, [sevenDaysAgo.toISOString(), limit, offset]);

    if (jobs.rows.length > 0) {
      // Append the full image URL to each job object
      const jobsWithImageUrl = jobs.rows.map(job => ({
        ...job,
        imageUrl: `${hostname}/uploads/${job.image}`,
      }));
      res.json(jobsWithImageUrl);
    } else {
      res.status(404).json({ error: "No jobs found" });
    }
  } catch (error) {
    console.error(`Error fetching all jobs: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve jobs" });
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


// Route to update a job (admin access only)
app.put("/api/jobs/:id", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { id } = req.params;
  const { companyname, title, description, apply_link, url, salary, location, job_type, experience, batch, job_uploader } = req.body;
  const newImage = req.file ? req.file.filename : null;

  try {
    const existingJob = await pool.query("SELECT * FROM job WHERE id = $1;", [id]);

    if (!existingJob.rows.length) {
      return res.status(404).json({ error: "Job not found" });
    }

    const oldImage = existingJob.rows[0].image;

    if (newImage && oldImage) {
      // Delete the old image
      const oldImagePath = path.join(__dirname, "uploads", oldImage);
      await fs.unlink(oldImagePath).catch(() => null); // Ignore errors if file doesn't exist
    }

    const updateJobQuery = `
      UPDATE job
      SET companyname = $1, title = $2, description = $3, apply_link = $4, image = $5, url = $6, salary = $7, location = $8, job_type = $9, experience = $10, batch = $11, job_uploader = $12
      WHERE id = $13;
    `;

    await pool.query(updateJobQuery, [
      companyname,
      title,
      description,
      apply_link,
      newImage || oldImage, // Use new image if provided, else keep the old image
      url,
      salary,
      location,
      job_type,
      experience,
      batch,
      job_uploader,
      id,
    ]);

    res.json({ message: "Job updated successfully" });
  } catch (error) {
    console.error(`Error updating job: ${error.message}`);
    res.status(500).json({ error: "Failed to update job" });
  }
});

// Route to delete a job (admin access only)
app.delete("/api/jobs/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const existingJob = await pool.query("SELECT * FROM job WHERE id = $1;", [id]);

    if (!existingJob.rows.length) {
      return res.status(404).json({ error: "Job not found" });
    }

    const job = existingJob.rows[0];
    const imagePath = path.join(__dirname, "uploads", job.image);

    // Delete the image file
    await fs.unlink(imagePath).catch(() => null); // Ignore errors if file doesn't exist

    const deleteJobQuery = `DELETE FROM job WHERE id = $1;`;
    await pool.query(deleteJobQuery, [id]);

    res.json({ message: "Job deleted successfully" });
  } catch (error) {
    console.error(`Error deleting job: ${error.message}`);
    res.status(500).json({ error: "Failed to delete job" });
  }
});

// Route to add a new job (admin access only, with validation)
app.post(
  "/api/jobs",
  upload.single("image"),
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { companyname, title, description, apply_link, url, salary, location, job_type, experience, batch, job_uploader } = req.body;
    const imagePath = req.file ? req.file.filename : null;

    if (!imagePath) {
      return res.status(400).json({ error: "Image file is required." });
    }

    try {
      const insertJobQuery = `
        INSERT INTO job (companyname, title, description, apply_link, image, url, salary, location, job_type, experience, batch, job_uploader)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);
      `;
      await pool.query(insertJobQuery, [companyname, title, description, apply_link, imagePath, url, salary, location, job_type, experience, batch, job_uploader]);
      res.status(201).json({ message: "Job added successfully" });
    } catch (error) {
      console.error(`Error adding job: ${error.message}`);
      res.status(500).json({ error: "Failed to add job" });
    }
  }
);

// Fetch job by company name and job URL
// Fetch job by company name and job URL
app.get('/api/jobs/company/:companyname/:url', async (req, res) => {
  const { companyname, url } = req.params;

  const getJobByCompanyNameQuery = `
    SELECT * FROM job WHERE LOWER(companyname) = LOWER($1) AND LOWER(url) = LOWER($2);
  `;

  try {
    const job = await pool.query(getJobByCompanyNameQuery, [companyname, url]);

    if (job.rows.length) {
      const jobWithImageUrl = {
        ...job.rows[0],
        imageUrl: `${hostname}/uploads/${job.rows[0].image}` // Add image URL
      };
      res.json(jobWithImageUrl);
    } else {
      res.status(404).json({ error: "Job not found" });
    }
  } catch (error) {
    console.error(`Error fetching job by company name and URL: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch job" });
  }
});

// Fetch the latest popup content
// Fetch the latest popup content
app.get("/api/popup", async (req, res) => {
  try {
    const popupResult = await pool.query("SELECT * FROM popup_content ORDER BY created_at DESC LIMIT 1;");
    const popup = popupResult.rows[0];
    
    if (popup) {
      // Append the full image URL to the popup if an image exists
      const popupWithImageUrl = popup.image
        ? { ...popup, imageUrl: `${hostname}/uploads/${popup.image}` }
        : popup;  // If no image, return the popup as is

      res.json({ popup: popupWithImageUrl });
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


app.post(
  "/api/popup/adminpanel",
  authenticateToken,
  authorizeAdmin,
  upload.single("image"),
  async (req, res) => {
    const { popup_heading, popup_text, popup_routing_link, popup_belowtext } = req.body;
    const imagePath = req.file ? req.file.filename : null;

    if (!imagePath) {
      return res.status(400).json({ error: "Image file is required." });
    }

    try {
      const insertPopQuery = `
        INSERT INTO popup_content (popup_heading, popup_text, image, popup_belowtext, popup_routing_link)
        VALUES ($1, $2, $3, $4, $5);
      `;
      await pool.query(insertPopQuery, [popup_heading, popup_text, imagePath, popup_belowtext, popup_routing_link]);
      res.status(201).json({ message: "Popup added successfully" });
    } catch (error) {
      console.error(`Error adding popup: ${error.message}`);
      res.status(500).json({ error: "Failed to add popup" });
    }
  }
);
// Admin Panel: Update specific popup content
app.put("/api/popup/adminpanel/:id", authenticateToken, authorizeAdmin, upload.single("image"), async (req, res) => {
  const { id } = req.params;
  const { popup_heading, popup_text, popup_belowtext, popup_routing_link } = req.body;
  const newImage = req.file ? req.file.filename : null;

  try {
    const existingPopup = await pool.query("SELECT * FROM popup_content WHERE id = $1;", [id]);

    if (!existingPopup.rows.length) {
      return res.status(404).json({ error: "Popup not found" });
    }

    const oldImage = existingPopup.rows[0].image;

    if (newImage && oldImage) {
      // Delete the old image
      const oldImagePath = path.join(__dirname, "uploads", oldImage);
      await fs.unlink(oldImagePath).catch(() => null); // Ignore errors if file doesn't exist
    }

    const updatePopupQuery = `
      UPDATE popup_content
      SET popup_heading = $1, popup_text = $2, popup_belowtext = $3, popup_routing_link = $4, image = $5
      WHERE id = $6;
    `;

    await pool.query(updatePopupQuery, [
      popup_heading,
      popup_text,
      popup_belowtext,
      popup_routing_link,
      newImage || oldImage, // Use new image if provided, else keep the old image
      id,
    ]);

    res.json({ message: "Popup content updated successfully" });
  } catch (error) {
    console.error(`Error updating popup content: ${error.message}`);
    res.status(500).json({ error: "Failed to update popup content" });
  }
});


// Admin Panel: Delete specific popup content by ID
app.delete("/api/popup/adminpanel/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const existingPopup = await pool.query("SELECT * FROM popup_content WHERE id = $1;", [id]);

    if (!existingPopup.rows.length) {
      return res.status(404).json({ error: "Popup not found" });
    }

    const popup = existingPopup.rows[0];
    const imagePath = path.join(__dirname, "uploads", popup.image);

    // Delete the image file
    await fs.unlink(imagePath).catch(() => null); // Ignore errors if file doesn't exist

    const deletePopupQuery = `DELETE FROM popup_content WHERE id = $1;`;
    await pool.query(deletePopupQuery, [id]);

    res.json({ message: "Popup content deleted successfully" });
  } catch (error) {
    console.error(`Error deleting popup content: ${error.message}`);
    res.status(500).json({ error: "Failed to delete popup content" });
  }
});




app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});


pool.connect()
  .then(() => console.log('Connected to PostgreSQL database'))
  .catch((err) => console.error('Database connection error:', err.stack));

// Root route
app.get("/", (req, res) => {
  res.send("Welcome to the Job Card Details API!");
});

// Middleware for error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

// Connect to the database and start the server
initializeDbAndServer();