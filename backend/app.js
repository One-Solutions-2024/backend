// Import required modules
const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const cors = require("cors");
const helmet = require("helmet");
const { body, validationResult } = require("express-validator");
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const mongoose = require("mongoose"); // For MongoDB
const fs = require("fs").promises; // For reading files
require("dotenv").config(); // Load environment variables

// Utility to convert slug back to a normal name
const convertSlugToName = (slug) => slug.replace(/-/g, ' ').toLowerCase();

// Use the MONGODB_URI from the .env file
const mongoURI = process.env.MONGODB_URI;
const PORT = process.env.PORT || 3000;
const databasePath = path.join(__dirname, process.env.DB_PATH || "jobs.db");

// Check if required environment variables are set
if (!mongoURI) {
  console.error("MONGODB_URI is not set in the environment variables.");
  process.exit(1);
}

// Initialize Express app
const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet()); // Basic security headers
app.use(morgan('combined')); // Logging

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter); // Apply rate limiting to all routes

// Database connection variable
let database = null;

// MongoDB model for visitor tracking (example)
const PageviewSchema = new mongoose.Schema({
  ip: String,
  views: { type: Number, default: 1 },
});

const Pageview = mongoose.model("Pageview", PageviewSchema);

// Initialize database and server
const initializeDbAndServer = async () => {
  try {
    database = await open({
      filename: databasePath,
      driver: sqlite3.Database,
    });

    // Create the job table if it doesn't exist
    // Create the job table if it doesn't exist
await database.run(`
  CREATE TABLE IF NOT EXISTS job (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    companyname TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    apply_link TEXT NOT NULL,
    image_link TEXT NOT NULL,
    url TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP -- Add this line
  );
`);


    // Insert jobs if table is empty (including image links)
    const jobsCount = await database.get(`SELECT COUNT(*) as count FROM job;`);
    if (jobsCount.count === 0) {
      const data = await fs.readFile("jobs.json", "utf8");
      const jobList = JSON.parse(data); // Parse the JSON data into a JavaScript object

      // Insert each job into the database
      const insertJobQuery = `
        INSERT INTO job (companyname, title, description, apply_link, image_link, url)
        VALUES (?, ?, ?, ?, ?, ?);
      `;

      for (const job of jobList) {
        await database.run(insertJobQuery, [
          job.companyname,
          job.title,
          job.description,
          job.apply_link,
          job.image_link,
          job.url,
        ]);
      }

      console.log("Job data has been imported successfully.");
    }

    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}/`);
    });

  } catch (error) {
    console.error(`Error initializing the database: ${error.message}`);
    process.exit(1); // Exit the process with an error code
  }
};

// Middleware for error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Route to get all jobs with pagination
app.get("/api/jobs", async (req, res) => {
  const { page = 1, limit = 8 } = req.query; // Pagination query params

  try {
    const offset = (page - 1) * parseInt(limit);
    // Get current timestamp
    const currentTime = new Date();
    // Calculate timestamp for 7 days ago
    const sevenDaysAgo = new Date(currentTime.setDate(currentTime.getDate() - 7));

    const getAllJobsQuery = `
      SELECT *, 
      CASE 
        WHEN createdAt >= ? THEN 1 
        ELSE 0 
      END as isNew 
      FROM job 
      ORDER BY isNew DESC, createdAt DESC 
      LIMIT ? OFFSET ?;
    `;
    
    const jobs = await database.all(getAllJobsQuery, [sevenDaysAgo.toISOString(), limit, offset]); // Parameterized query

    if (jobs.length > 0) {
      res.json(jobs);
    } else {
      res.status(404).json({ error: "No jobs found" });
    }
  } catch (error) {
    console.error(`Error fetching all jobs: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve jobs" });
  }
});


// Route to update a job
app.put("/api/jobs/:id", async (req, res) => {
  const { id } = req.params;
  const { companyname, title, description, apply_link, image_link, url } = req.body;

  try {
    // Check if the job exists
    const existingJob = await database.get("SELECT * FROM job WHERE id = ?", [id]);
    if (!existingJob) {
      return res.status(404).json({ error: "Job not found" });
    }

    const updateJobQuery = `
      UPDATE job
      SET companyname = ?, title = ?, description = ?, apply_link = ?, image_link = ?, url = ?
      WHERE id = ?;
    `;
    await database.run(updateJobQuery, [companyname, title, description, apply_link, image_link, url,  id]);
    res.json({ message: "Job updated successfully" });
  } catch (error) {
    console.error(`Error updating job: ${error.message}`);
    res.status(500).json({ error: "Failed to update job" });
  }
});

// Route to delete a job
app.delete("/api/jobs/:id", async (req, res) => {
  const { id } = req.params;

  try {
    // Check if the job exists
    const existingJob = await database.get("SELECT * FROM job WHERE id = ?", [id]);
    if (!existingJob) {
      return res.status(404).json({ error: "Job not found" });
    }

    const deleteJobQuery = `DELETE FROM job WHERE id = ?;`;
    await database.run(deleteJobQuery, [id]);
    res.json({ message: "Job deleted successfully" });
  } catch (error) {
    console.error(`Error deleting job: ${error.message}`);
    res.status(500).json({ error: "Failed to delete job" });
  }
});

// Route to add a new job (with validation)
app.post(
  "/api/jobs",
  [
    body("companyname").notEmpty(),
    body("title").notEmpty(),
    body("description").notEmpty(),
    body("apply_link").isURL(),
    body("image_link").isURL(),
    body("url").isURL(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { companyname, title, description, apply_link, image_link, url } = req.body;

    try {
      const insertJobQuery = `
        INSERT INTO job (companyname, title, description, apply_link, image_link, url)
        VALUES (?, ?, ?, ?, ?, ?);
      `;
      await database.run(insertJobQuery, [companyname, title, description, apply_link, image_link, url]);
      res.status(201).json({ message: "Job added successfully" });
    } catch (error) {
      console.error("Failed to add job:", error);
      res.status(500).json({ error: "Failed to add job" });
    }
  }
);

// Fetch job by company name and job URL
app.get("/api/jobs/company/:companyname/:url", async (req, res) => {
  const { companyname, url } = req.params;
  
  const getJobByCompanyNameQuery = `
    SELECT * FROM job WHERE LOWER(companyname) = LOWER(?) AND LOWER(job_url) = LOWER(?);`; 
  // Ensure both company name and job URL match

  try {
    const job = await database.get(getJobByCompanyNameQuery, [companyname, url]);

    if (job) {
      res.json(job);
    } else {
      res.status(404).json({ error: "Job not found" });
    }
  } catch (error) {
    console.error(`Error fetching job by company name and URL: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch job" });
  }
});





// Route to track visitor IPs and views
app.get("/track-visitor", async (req, res) => {
  const visitorIp = req.headers["x-forwarded-for"] || req.connection.remoteAddress;

  try {
    let visitor = await Pageview.findOne({ ip: visitorIp });

    if (!visitor) {
      visitor = new Pageview({ ip: visitorIp, views: 1 });
      await visitor.save();
    } else {
      visitor.views += 1;
      await visitor.save();
    }

    const uniqueViewsCount = await Pageview.countDocuments();
    res.json({ uniqueViews: uniqueViewsCount });
  } catch (error) {
    console.error("Error tracking visitor:", error);
    res.status(500).json({ error: "Failed to track visitor" });
  }
});

// Root route
app.get("/", (req, res) => {
  res.send("Welcome to the Job Card Details API!");
});

// MongoDB connection (example)
mongoose
  .connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Start the application
initializeDbAndServer();
