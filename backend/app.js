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
const { createServer } = require("http");
const { Server } = require("socket.io");

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

const server = createServer(app);
// Server-side setup (Node.js/Express)
const io = require('socket.io')(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket', 'polling']
});

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  // Handle direct chat room joining
  socket.on('join_direct', ({ userId, recipientId }) => {
    const roomName = `direct-${[userId, recipientId].sort().join('-')}`;
    socket.join(roomName);
    console.log(`User ${userId} joined direct chat room: ${roomName}`);
  });

  // Handle direct messages
  socket.on('direct_message', async (message) => {
    try {
      // Save message to database
      const savedMessage = await saveMessageToDB(message);
      
      // Determine the room name
      const roomName = `direct-${[message.sender_id, message.recipient_id].sort().join('-')}`;
      
      // Emit to all in the room
      io.to(roomName).emit('direct_message', savedMessage);
    } catch (error) {
      console.error('Error handling direct message:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

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


const getClientIp = (req) => {
  const ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  return ip.split(",")[0].trim(); // Handles proxies and IPv6
};

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
       // Check if there are any existing admins
    const existingAdmins = await pool.query("SELECT COUNT(*) FROM admins");
    const isFirstAdmin = existingAdmins.rows[0].count == 0;  // If no admins exist, it's the first admin
    
    // Set status to "approved" if first admin, otherwise "pending"
    const adminStatus = isFirstAdmin ? "approved" : "pending";

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
        INSERT INTO admin (adminname, username, password, phone, admin_image_link, status)
        VALUES ($1, $2, $3, $4, $5, $6) RETURNING *;
      `;
      const newAdmin = await pool.query(insertAdminQuery, [
        adminname,
        username,
        hashedPassword,
        phone,
        admin_image_link || null,
        adminStatus,
      ]);
      res.status(201).json({
        message: isFirstAdmin
          ? "First admin registered successfully! You can now log in."
          : "Registration successful! Awaiting admin approval.", adminId: newAdmin.rows[0].id
      });
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

    if (admin.status !== "approved") {
      return res.status(403).json({ error: "Admin approval is pending. Please wait for approval." });
    }
    // Generate JWT
    // Generate a token (if using JWT)
    res.json({ message: "Login successful!" });
  } catch (error) {
    console.error(`Error during admin login: ${error.message}`);
    res.status(500).json({ error: "Failed to log in" });
  }
});

app.put("/api/admin/reject/:id", async (req, res) => {
  const { id } = req.params;

  try {
    await pool.query("UPDATE admins SET status = 'rejected' WHERE id = $1", [id]);

    res.json({ message: "Admin rejected successfully." });
  } catch (error) {
    res.status(500).json({ error: "Error rejecting admin." });
  }
});
app.put("/api/admin/approve/:id", async (req, res) => {
  const { id } = req.params;

  try {
    // Update the status to 'approved'
    await pool.query("UPDATE admins SET status = 'approved' WHERE id = $1", [id]);

    res.json({ message: "Admin approved successfully!" });
  } catch (error) {
    res.status(500).json({ error: "Error approving admin." });
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
    // Add tables for admin functionality

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

    // Add tables for chat functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_rooms (
        id SERIAL PRIMARY KEY,
        room_name TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        room_id INT NOT NULL REFERENCES chat_rooms(id),
        sender_id INT NOT NULL REFERENCES admin(id),
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

          // Create table for direct messages (one-to-one chats)
      await pool.query(`
        CREATE TABLE IF NOT EXISTS direct_messages (
          id SERIAL PRIMARY KEY,
          sender_id INT NOT NULL REFERENCES admin(id),
          recipient_id INT NOT NULL REFERENCES admin(id),
          message TEXT NOT NULL,
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
    

    // Start server
    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}/`);
    });

  } catch (error) {
    console.error(`Error initializing the database: ${error.message}`);
    process.exit(1);
  }
};

// Chat Routes
app.post("/api/chat/rooms", authenticateToken, authorizeAdmin, async (req, res) => {
  const { room_name } = req.body;

  try {
    const insertRoomQuery = `
      INSERT INTO chat_rooms (room_name)
      VALUES ($1)
      RETURNING *;
    `;
    const newRoom = await pool.query(insertRoomQuery, [room_name]);
    res.status(201).json(newRoom.rows[0]);
  } catch (error) {
    console.error(`Error creating chat room: ${error.message}`);
    res.status(500).json({ error: "Failed to create chat room" });
  }
});

app.get("/api/chat/rooms", authenticateToken, async (req, res) => {
  try {
    const roomsQuery = "SELECT * FROM chat_rooms ORDER BY created_at DESC;";
    const rooms = await pool.query(roomsQuery);
    res.json(rooms.rows);
  } catch (error) {
    console.error(`Error fetching chat rooms: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch chat rooms" });
  }
});

// Updated group messages endpoint
app.post("/api/chat/messages", authenticateToken, async (req, res) => {
  const { room_id, message } = req.body;
  const sender_id = req.user.id;

  try {
    const insertMessageQuery = `
      INSERT INTO chat_messages (room_id, sender_id, message)
      VALUES ($1, $2, $3)
      RETURNING *;
    `;
    const newMessage = await pool.query(insertMessageQuery, [room_id, sender_id, message]);
    
    // Emit the new message to the room
    const fullMessage = {
      ...newMessage.rows[0],
      adminname: req.user.adminname,
      admin_image_link: req.user.admin_image_link
    };
    
    io.to(room_id).emit("group_message", fullMessage);
    
    res.status(201).json(newMessage.rows[0]);
  } catch (error) {
    console.error(`Error sending message: ${error.message}`);
    res.status(500).json({ error: "Failed to send message" });
  }
});

app.get("/api/chat/messages/:room_id", authenticateToken, async (req, res) => {
  const { room_id } = req.params;

  try {
    const messagesQuery = `
      SELECT cm.*, a.adminname, a.admin_image_link
      FROM chat_messages cm
      JOIN admin a ON cm.sender_id = a.id
      WHERE cm.room_id = $1
      ORDER BY cm.created_at ASC;
    `;
    const messages = await pool.query(messagesQuery, [room_id]);
    res.json(messages.rows);
  } catch (error) {
    console.error(`Error fetching messages: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});
// GET direct messages endpoint 
app.get(
  "/api/chat/direct-messages/:senderId/:recipientId",
  authenticateToken,
  async (req, res) => {
    const { senderId, recipientId } = req.params;
    
    // Convert to integers and validate
    const senderIdInt = parseInt(senderId, 10);
    const recipientIdInt = parseInt(recipientId, 10);
    
    if (isNaN(senderIdInt) || isNaN(recipientIdInt)) {
      return res.status(400).json({ error: "Invalid sender or recipient ID" });
    }

    try {
      const messagesQuery = `
        SELECT dm.*, a.adminname, a.admin_image_link
        FROM direct_messages dm
        JOIN admin a ON dm.sender_id = a.id
        WHERE (dm.sender_id = $1 AND dm.recipient_id = $2)
           OR (dm.sender_id = $2 AND dm.recipient_id = $1)
        ORDER BY dm.created_at ASC;
      `;
      const result = await pool.query(messagesQuery, [senderIdInt, recipientIdInt]);
      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching direct messages:", error.message);
      res.status(500).json({ error: "Failed to fetch direct messages" });
    }
  }
);
// POST direct messages endpoint
// Modified direct messages endpoint
app.post("/api/chat/direct-messages", authenticateToken, async (req, res) => {
  const { recipient_id, message } = req.body;
  const sender_id = req.user.id; // Get from token

  try {
    const insertQuery = `
      INSERT INTO direct_messages (sender_id, recipient_id, message)
      VALUES ($1, $2, $3)
      RETURNING *;
    `;
    const result = await pool.query(insertQuery, [sender_id, recipient_id, message]);
    
    // Emit the new message via Socket.io
    const newMessage = {
      ...result.rows[0],
      adminname: req.user.adminname,
      admin_image_link: req.user.admin_image_link
    };
    
    io.to(`direct_${sender_id}_${recipient_id}`)
      .to(`direct_${recipient_id}_${sender_id}`)
      .emit("direct_message", newMessage);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Error sending direct message:", error.message);
    res.status(500).json({ error: "Failed to send direct message" });
  }
});




// Route to get all admins (admin access only)
app.get("/api/admins", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const adminsQuery = `
      SELECT 
        id, 
        adminname, 
        username, 
        phone, 
        admin_image_link, 
        createdat AS "createdAt"
      FROM admin 
      ORDER BY createdat DESC;
    `;
    const result = await pool.query(adminsQuery);
    res.json(result.rows);
  } catch (error) {
    console.error(`Error fetching admins: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve admins" });
  }
});

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

// Route to update admin details
app.put(
  "/api/admin/update",
  authenticateToken, // Ensure the user is authenticated
  [
    body("adminname"),
    body("username"),
    body("phone"),
    body("admin_image_link"),
    body("password"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { adminname, username, phone, admin_image_link, password } = req.body;
    const adminId = req.user.id; // Get admin ID from the token

    try {
      // Check if the username or phone already exists for another admin
      if (username || phone) {
        const existingAdmin = await pool.query(
          "SELECT * FROM admin WHERE (username = $1 OR phone = $2) AND id != $3;",
          [username, phone, adminId]
        );

        if (existingAdmin.rows.length) {
          return res.status(400).json({ error: "Username or phone already in use by another admin" });
        }
      }

      // Prepare fields for update
      const updates = [];
      const values = [];
      let index = 1;

      if (adminname) {
        updates.push(`adminname = $${index++}`);
        values.push(adminname);
      }
      if (username) {
        updates.push(`username = $${index++}`);
        values.push(username);
      }
      if (phone) {
        updates.push(`phone = $${index++}`);
        values.push(phone);
      }
      if (admin_image_link) {
        updates.push(`admin_image_link = $${index++}`);
        values.push(admin_image_link);
      }
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        updates.push(`password = $${index++}`);
        values.push(hashedPassword);
      }

      if (updates.length === 0) {
        return res.status(400).json({ error: "No fields to update" });
      }

      values.push(adminId); // Add admin ID as the last parameter

      const updateQuery = `
        UPDATE admin
        SET ${updates.join(", ")}
        WHERE id = $${index};
      `;

      await pool.query(updateQuery, values);
      res.json({ message: "Admin details updated successfully" });
    } catch (error) {
      console.error(`Error updating admin details: ${error.message}`);
      res.status(500).json({ error: "Failed to update admin details" });
    }
  }
);


// Route to reset password
app.post("/api/admin/forgot-password", async (req, res) => {
  const { username, newPassword } = req.body;

  // Validate input
  if (!username || !newPassword) {
    return res.status(400).json({ error: "Username and new password are required" });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters long" });
  }

  try {
    // Check if the admin exists
    const adminQuery = `SELECT id FROM admin WHERE username = $1;`;
    const adminResult = await pool.query(adminQuery, [username]);

    if (!adminResult.rows.length) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const adminId = adminResult.rows[0].id;

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the password in the database
    const updatePasswordQuery = `
      UPDATE admin 
      SET password = $1 
      WHERE id = $2;
    `;
    await pool.query(updatePasswordQuery, [hashedPassword, adminId]);

    res.json({ message: "Password reset successfully" });
  } catch (error) {
    console.error(`Error resetting password: ${error.message}`);
    res.status(500).json({ error: "Failed to reset password" });
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
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch } = req.body;
    const adminId = req.user.id; // Get admin ID from the token

    try {
      // Fetch admin details to get adminname
      const adminQuery = "SELECT adminname FROM admin WHERE id = $1;";
      const adminResult = await pool.query(adminQuery, [adminId]);
      const admin = adminResult.rows[0];

      if (!admin) {
        return res.status(404).json({ error: "Admin not found" });
      }

      const jobUploader = admin.adminname; // Use adminname as job uploader

      const insertJobQuery = `
        INSERT INTO job (companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, job_uploader)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);
      `;
      await pool.query(insertJobQuery, [companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, jobUploader]);
      res.status(201).json({ message: "Job added successfully" });
    } catch (error) {
      console.error(`Error adding job: ${error.message}`);
      res.status(500).json({ error: "Failed to add job" });
    }
  }
);

// Route to update a job (admin access only)
app.put("/api/jobs/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const { companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch } = req.body;

  try {
    const existingJob = await pool.query("SELECT * FROM job WHERE id = $1;", [id]);

    if (!existingJob.rows.length) {
      return res.status(404).json({ error: "Job not found" });
    }

    // Fetch admin details to get adminname
    const adminId = req.user.id; // Get admin ID from the token
    const adminQuery = "SELECT adminname FROM admin WHERE id = $1;";
    const adminResult = await pool.query(adminQuery, [adminId]);
    const admin = adminResult.rows[0];

    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const jobUploader = admin.adminname; // Use adminname as job uploader

    const updateJobQuery = `
      UPDATE job
      SET companyname = $1, title = $2, description = $3, apply_link = $4, image_link = $5, url = $6, salary = $7, location = $8, job_type = $9, experience = $10, batch = $11, job_uploader = $12
      WHERE id = $13;
    `;
    await pool.query(updateJobQuery, [companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, jobUploader, id]);
    res.json({ message: "Job updated successfully" });
  } catch ( error) {
    console.error(`Error updating job: ${error.message}`);
    res.status(500).json({ error: "Failed to update job" });
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