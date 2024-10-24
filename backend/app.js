// Import required modules
const express = require("express");
const { Pool } = require("pg");  // Replacing sqlite with pg
const path = require("path");
const cors = require("cors");
const helmet = require("helmet");
const { body, validationResult } = require("express-validator");
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const fs = require("fs").promises; // For reading files
require("dotenv").config(); // Load environment variables

const PORT = process.env.PORT || 3000;

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
app.use(morgan('combined')); // Logging

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter); // Apply rate limiting to all routes

// Middleware for error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Initialize the database and server
const initializeDbAndServer = async () => {
  try {
    // Create the job table if it doesn't exist (PostgreSQL-specific SQL)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS job (
        id SERIAL PRIMARY KEY,
        companyname TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        apply_link TEXT NOT NULL,
        image_link TEXT NOT NULL,
        url TEXT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Insert jobs if table is empty (including image links)
    const jobsCountResult = await pool.query('SELECT COUNT(*) as count FROM job;');
    const jobsCount = jobsCountResult.rows[0].count;

    if (jobsCount == 0) {
      const data = await fs.readFile("jobs.json", "utf8");
      const jobList = JSON.parse(data); // Parse the JSON data into a JavaScript object

      const insertJobQuery = `
        INSERT INTO job (companyname, title, description, apply_link, image_link, url)
        VALUES ($1, $2, $3, $4, $5, $6);
      `;

      for (const job of jobList) {
        await pool.query(insertJobQuery, [
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

// Route to get all jobs with pagination
app.get("/api/jobs", async (req, res) => {
  const { page = 1, limit = 8 } = req.query; // Pagination query params

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
      res.json(jobs.rows);
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
    const existingJob = await pool.query("SELECT * FROM job WHERE id = $1;", [id]);

    if (!existingJob.rows.length) {
      return res.status(404).json({ error: "Job not found" });
    }

    const updateJobQuery = `
      UPDATE job
      SET companyname = $1, title = $2, description = $3, apply_link = $4, image_link = $5, url = $6
      WHERE id = $7;
    `;
    await pool.query(updateJobQuery, [companyname, title, description, apply_link, image_link, url, id]);
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
    const existingJob = await pool.query("SELECT * FROM job WHERE id = $1;", [id]);

    if (!existingJob.rows.length) {
      return res.status(404).json({ error: "Job not found" });
    }

    const deleteJobQuery = `DELETE FROM job WHERE id = $1;`;
    await pool.query(deleteJobQuery, [id]);
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
    body("url").notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { companyname, title, description, apply_link, image_link, url } = req.body;

    try {
      const insertJobQuery = `
        INSERT INTO job (companyname, title, description, apply_link, image_link, url)
        VALUES ($1, $2, $3, $4, $5, $6);
      `;
      await pool.query(insertJobQuery, [companyname, title, description, apply_link, image_link, url]);
      res.status(201).json({ message: "Job added successfully" });
    } catch (error) {
      console.error("Failed to add job:", error);
      res.status(500).json({ error: "Failed to add job" });
    }
  }
);

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

app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// Root route
app.get("/", (req, res) => {
  res.send("Welcome to the Job Card Details API!");
});

pool.connect()
  .then(() => console.log('Connected to PostgreSQL database'))
  .catch((err) => console.error('Database connection error:', err.stack));


// Start the application
initializeDbAndServer();
