
// Import required modules
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const helmet = require("helmet");
const { body, validationResult } = require("express-validator");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");

const fs = require("fs").promises;
const bcrypt = require("bcrypt");
require("dotenv").config(); // Load environment variables

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "MY_SECRET_TOKEN"; // JWT secret from environment variables


// Initialize PostgreSQL pool using environment variable
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // This bypasses certificate verification
  },
});

// Initialize Express app
const app = express();

const getClientIp = (req) => {
  const ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  return ip.split(",")[0].trim(); // Handles proxies and IPv6
};

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet()); // Basic security headers
app.use(morgan("combined")); // Logging


// Configure CORS for external access
const corsOptions = {
  origin: "*", // Replace "*" with specific domains for production
};
app.use(cors(corsOptions));

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: "Token required" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ error: "Invalid token" });
      req.user = user; // Save decoded token data (e.g., user id and role)
      next();
  });
};
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
  }
  next();
};


// Route for admin registration
app.post(
  "/api/admin/register",
  [
    body("adminname").notEmpty(),
    body("username").notEmpty(),
    body("password").isLength({ min: 6 }),
    body("phone").isMobilePhone(),
    body("admin_image_link").isURL(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { adminname, username, password, phone, admin_image_link } = req.body;

    try {
      // Check if username or phone already exists
      const existingAdmin = await pool.query(
        "SELECT * FROM admin WHERE username = $1 OR phone = $2;",
        [username, phone]
      );
      if (existingAdmin.rows.length) {
        return res.status(400).json({ error: "Admin with this username or phone already exists" });
      }

      // Hash the password before saving
      const hashedPassword = await bcrypt.hash(password, 10);

      const insertAdminQuery = `
        INSERT INTO admin (adminname, username, password, phone, admin_image_link)
        VALUES ($1, $2, $3, $4, $5) RETURNING id;
      `;
      const newAdmin = await pool.query(insertAdminQuery, [
        adminname,
        username,
        hashedPassword,
        phone,
        admin_image_link || null,
      ]);
      res.status(201).json({ message: "Admin registered successfully", adminId: newAdmin.rows[0].id });
    } catch (error) {
      console.error(`Error registering admin: ${error.message}`);
      res.status(500).json({ error: "Failed to register admin" });
    }
  }
);

// Route for admin login
app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if admin exists
    const adminQuery = "SELECT * FROM admin WHERE username = $1;";
    const adminResult = await pool.query(adminQuery, [username]);

    if (!adminResult.rows.length) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const admin = adminResult.rows[0];

    // Verify password
    const passwordMatch = await bcrypt.compare(password, admin.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Generate JWT
    const token = jwt.sign({ id: admin.id, username: admin.username, role: "admin" }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({
      message: "Login successful",
      token,
      admin: {
        adminname: admin.adminname,
        username: admin.username,
        phone: admin.phone,
        admin_image_link: admin.admin_image_link,
      },
    });
  } catch (error) {
    console.error(`Error during admin login: ${error.message}`);
    res.status(500).json({ error: "Failed to log in" });
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
        image_link TEXT NOT NULL,
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
      CREATE TABLE IF NOT EXISTS job_viewers (
        id SERIAL PRIMARY KEY,
        job_id INT NOT NULL REFERENCES job(id),
        ip_address TEXT NOT NULL,
        viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (job_id, ip_address)
    );
    `);

    // Create popup_content table
    await pool.query(`
          CREATE TABLE IF NOT EXISTS popup_content (
          id SERIAL PRIMARY KEY,
          popup_heading TEXT NOT NULL,
          popup_text TEXT NOT NULL,
          popup_link TEXT NOT NULL,
          popup_belowtext TEXT NOT NULL,
          popup_routing_link TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);


    const popUpCountResult = await pool.query("SELECT COUNT(*) as count FROM popup_content");
    const popupCount = popUpCountResult.rows[0].count;

    if (popupCount == 0) {
      try {
        const data = await fs.readFile("pops.json", "utf8");
        const popList = JSON.parse(data); // popList should be an array

        if (!Array.isArray(popList)) {
          throw new Error("pops.json content is not an array");
        }

        const insertPopQuery = `
          INSERT INTO popup_content (popup_heading, popup_text, popup_link, popup_belowtext, popup_routing_link)
          VALUES ($1, $2, $3, $4, $5);
        `;

        for (const popup_content of popList) {
          await pool.query(insertPopQuery, [
            popup_content.popup_heading,
            popup_content.popup_text,
            popup_content.popup_link,
            popup_content.popup_belowtext,
            popup_content.popup_routing_link,
          ]);
        }
        console.log("Pop Data Imported Successfully");
      } catch (error) {
        console.error("Error reading or processing pops.json:", error.message);
        throw error; // rethrow the error to prevent the server from starting
      }
    }


    // Insert jobs if table is empty
    const jobsCountResult = await pool.query("SELECT COUNT(*) as count FROM job;");
    const jobsCount = jobsCountResult.rows[0].count;

    if (jobsCount == 0) {
      const data = await fs.readFile("jobs.json", "utf8");
      const jobList = JSON.parse(data);

      const insertJobQuery = `
         INSERT INTO job (companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, job_uploader)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);
       `;

      for (const job of jobList) {
        await pool.query(insertJobQuery, [
          job.companyname,
          job.title,
          job.description,
          job.apply_link,
          job.image_link,
          job.url,
          job.salary,
          job.location,
          job.job_type,
          job.experience,
          job.batch,
          job.job_uploader,
        ]);
      }
      console.log("Job data has been imported successfully.");
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin (
        id SERIAL PRIMARY KEY,
        adminname TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        phone TEXT NOT NULL,
        admin_image_link TEXT,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Check if there are any admins in the table
    const adminCountResult = await pool.query("SELECT COUNT(*) as count FROM admin;");
    const adminCount = adminCountResult.rows[0].count;
    if (adminCount == 0) {
      const data = await fs.readFile("admin.json", "utf8");
      const adminList = JSON.parse(data);

      const insertAdminQuery = `
         INSERT INTO admin (adminname, username, password, phone, admin_image_link)
         VALUES ($1, $2, $3, $4, $5);
       `;

      for (const admin of adminList) {
        await pool.query(insertAdminQuery, [
          admin.adminname,
          admin.username,
          admin.password,
          admin.phone,
          admin.admin_image_link,
        ]);
      }
      console.log("Admin data has been imported successfully.");
    }


    // Start server on 0.0.0.0 for external access
    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}/`);
    });


  } catch (error) {
    console.error(`Error initializing the database: ${error.message}`);
    process.exit(1);
  }
};


// Route to fetch admin's own details after login
app.get("/api/admin/me", authenticateToken, async (req, res) => {
  try {
    const { id } = req.user; // The ID is embedded in the token during login
    const adminQuery = "SELECT * FROM admin WHERE id = $1";
    const adminResult = await pool.query(adminQuery, [id]);

    if (!adminResult.rows.length) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const admin = adminResult.rows[0];
    res.json({
      adminname: admin.adminname,
      username: admin.username,
      phone: admin.phone,
      admin_image_link: admin.admin_image_link,
      createdAt: admin.createdAt,
    });
  } catch (error) {
    console.error(`Error fetching admin details: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve admin details" });
  }
});

app.put("/api/admindetails/update/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const { adminname, phone, admin_image_link } = req.body;

  try {
    // Check if admin exists
    const existingAdmin = await pool.query("SELECT id FROM admin WHERE id = $1;", [id]);

    if (!existingAdmin.rows.length) {
      return res.status(404).json({ error: "Admin not found" });
    }

    // Update admin details
    const updateAdminQuery = `
      UPDATE admin
      SET adminname = $1, phone = $2, admin_image_link = $3
      WHERE id = $4
      RETURNING *; -- Return the updated row
    `;
    const result = await pool.query(updateAdminQuery, [adminname, phone, admin_image_link, id]);

    // Respond with the updated admin data
    res.json({ message: "Admin updated successfully", admin: result.rows[0] });
  } catch (error) {
    console.error(`Error updating Admin: ${error.message}`);
    res.status(500).json({ error: "Failed to update Admin" });
  }
});



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
      res.json(jobs.rows);
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
app.put("/api/jobs/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const { companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, job_uploader } = req.body;

  try {
    const existingJob = await pool.query("SELECT * FROM job WHERE id = $1;", [id]);

    if (!existingJob.rows.length) {
      return res.status(404).json({ error: "Job not found" });
    }

    const updateJobQuery = `
      UPDATE job
      SET companyname = $1, title = $2, description = $3, apply_link = $4, image_link = $5, url = $6, salary = $7, location = $8, job_type = $9, experience = $10, batch = $11, job_uploader = $12
      WHERE id = $13;
    `;
    await pool.query(updateJobQuery, [companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, job_uploader, id]);
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
  authenticateToken,
  authorizeAdmin,
  [
    body("companyname").notEmpty(),
    body("title").notEmpty(),
    body("description").notEmpty(),
    body("apply_link").isURL(),
    body("image_link").isURL(),
    body("url").notEmpty(),
    body("salary").notEmpty(),
    body("location").notEmpty(),
    body("job_type").notEmpty(),
    body("experience").notEmpty(),
    body("batch").notEmpty(),
    body("job_uploader").notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, job_uploader } = req.body;

    try {
      const insertJobQuery = `
        INSERT INTO job (companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, job_uploader)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);
      `;
      await pool.query(insertJobQuery, [companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, job_uploader]);
      res.status(201).json({ message: "Job added successfully" });
    } catch (error) {
      console.error(`Error adding job: ${error.message}`);
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



app.post("/api/jobs/:id/view", async (req, res) => {
  const { id } = req.params;
  const ipAddress = getClientIp(req);

  try {
    const query = `
          INSERT INTO job_viewers (job_id, ip_address, viewed_at)
          VALUES ($1, $2, CURRENT_TIMESTAMP)
          ON CONFLICT (job_id, ip_address)
          DO UPDATE SET viewed_at = CURRENT_TIMESTAMP;
      `;
    await pool.query(query, [id, ipAddress]);
    res.status(200).json({ message: "View recorded successfully" });
  } catch (error) {
    console.error(`Error recording job view: ${error.message}`);
    res.status(500).json({ error: "Failed to record view" });
  }
});

app.get("/api/jobs/:id/viewers", async (req, res) => {
  const { id } = req.params;

  try {
    const query = `
          SELECT COUNT(DISTINCT ip_address) AS viewer_count
          FROM job_viewers
          WHERE job_id = $1;
      `;
    const result = await pool.query(query, [id]);
    res.json({ viewer_count: result.rows[0].viewer_count });
  } catch (error) {
    console.error(`Error fetching viewers count: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve viewer count" });
  }
});



// Fetch the latest popup content
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

app.post(
  "/api/popup/adminpanel",
  authenticateToken, authorizeAdmin,
  [
    body("popup_heading").notEmpty(),
    body("popup_text").notEmpty(),
    body("popup_link").isURL(),
    body("popup_routing_link").isURL(),
    body("popup_belowtext").notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { popup_heading, popup_text, popup_link, popup_routing_link, popup_belowtext } = req.body;
    try {
      const insertPopQuery = `
      INSERT INTO popup_content (popup_heading, popup_text, popup_link, popup_belowtext, popup_routing_link)
      VALUES ($1, $2, $3, $4, $5);
    `; await pool.query(insertPopQuery, [popup_heading, popup_text, popup_link, popup_belowtext, popup_routing_link]);
      res.status(201).json({ message: "Pop added successfully" });
    } catch (error) {
      console.error(`Error adding Pop: ${error.message}`);
      res.status(500).json({ error: "Failed to add Pop" });
    }

  }
)
// Admin Panel: Update specific popup content
app.put("/api/popup/adminpanel/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const { popup_heading, popup_text, popup_link, popup_routing_link, popup_belowtext } = req.body;

  try {
    const existingPopup = await pool.query("SELECT * FROM popup_content WHERE id = $1;", [id]);

    if (!existingPopup.rows.length) {
      return res.status(404).json({ error: "Popup not found" });
    }

    const updatePopupQuery = `
      UPDATE popup_content
      SET popup_heading = $1,
          popup_text = $2,
          popup_link = $3,
          popup_routing_link = $4,
          popup_belowtext = $5
      WHERE id = $6;
    `;
    await pool.query(updatePopupQuery, [popup_heading, popup_text, popup_link, popup_routing_link, popup_belowtext, id]);
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