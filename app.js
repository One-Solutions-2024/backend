const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const cors = require("cors");

const databasePath = path.join(__dirname, "jobs.db");

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

let database = null;

const initializeDbAndServer = async () => {
  try {
    database = await open({
      filename: databasePath,
      driver: sqlite3.Database,
    });

    // Modify the table to include an image_link column
    await database.run(`
      CREATE TABLE IF NOT EXISTS job (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        apply_link TEXT NOT NULL,
        instagram_link TEXT NOT NULL,
        youtube_link TEXT NOT NULL,
        image_link TEXT NOT NULL
      );
    `);

    // Insert jobs if table is empty (including image links)
    const jobsCount = await database.get(`SELECT COUNT(*) as count FROM job;`);
    if (jobsCount.count === 0) {
      await database.run(`
        INSERT INTO job (title, description, apply_link, instagram_link, youtube_link, image_link) VALUES 
        ('Associate - Projects', 
        'Possess a strong background in SAP EWM Testing, Demonstrate specialized skills in EWM, Exhibit excellent problem-solving abilities, Show proficiency in developing test plans, Have experience in defect tracking and resolution, Display strong communication skills, Be familiar with industry standards, Mentor and guide junior team members, Work Location: Hybrid', 
        'https://cognizant.taleo.net/careersection/Lateral/jobapply.ftl?job=00060120911&lang=en&source=CWS-13082&src=CWS-13082', 
        'https://instagram.com/job1', 
        'https://youtube.com/job1', 
        'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQSBLLLkyDaLgoJoJQMyzuwPUsTt1sW5kTaow&s'),

        ('QA Engineer', 
        'Bachelor’s degree or equivalent experience required, No prior experience required, Study or experience focused on one of the following or equivalent: quality engineering, quality systems, systems monitoring, computer systems management, Ability to clearly articulate ideas, such as current state and optimal state of a given system, Experience with test automation frameworks such as Selenium, Cypress, or Java tools preferred, Work Location: Bangalore', 
        'https://unstop.com/o/QYKRL4I?utm_medium=Share&utm_source=shortUrl', 
        'https://instagram.com/job2', 
        'https://youtube.com/job2', 
        'https://i0.wp.com/opportunitycell.com/wp-content/uploads/2022/12/KPMG-London.png?fit=1000%2C667&ssl=1'),

        ('Software Development Engineer', 
        'GE Digital Career 2024 Invites Students From Various Disciplines to apply for the Position of Software Development Engineer in Hyderabad, India, Freshers/Experienced, Bachelor’s Degree in Computer Science or “STEM” Majors (Science, Technology, Engineering and Math) with basic experience, Expertise in Java programming, particularly in Object-Oriented Programming (OOP) concepts, The ideal candidate should have a proven track record in implementing REST endpoints and a strong background in utilizing the Spring Boot framework, including Spring Security, Spring JPA, and Spring MVC, Proficient in front-end technologies like Angular, HTML5, and CSS, Write Unit Tests using JUnit for ensuring code quality and reliability, Experience with dependency management tools like Gradle or Maven for project build automation, Work on core data structures and algorithms and implement them using language of choice, Work Location: Hyderabad, India (Hybrid)', 
        'https://jobs.gecareers.com/global/en/apply?jobSeqNo=GE11GLOBALR3780300EXTERNALENGLOBAL&step=1&stepname=personalInformation', 
        'https://instagram.com/job3', 
        'https://youtube.com/job3', 
        'https://job4software.com/wp-content/uploads/2024/09/gettyimages-868982314-scaled.webp'),

        ('Device Associate', 
        'Graduate, preferably in a quantitative field of study with relevant experience of 0-1 years, Good communication skills, detail-oriented, and be a team player, Knowledge of QA methodology and tools, Gain understanding of the application test procedures and how to use applicable software and tools, Execute test instructions and report test results accurately and promptly, Report any deviations observed, Understand any changes in test instructions related to their assigned work', 
        'https://www.amazon.jobs/en/jobs/2769644/device-associate', 
        'https://instagram.com/job4', 
        'https://youtube.com/job4', 
        'https://etimg.etb2bimg.com/photo/91892300.cms'),

        ('International Voice Process-Hyderabad', 
        'Must be fluent in English, Excellent communication skills can apply, Both freshers and experienced candidates can apply, Graduation is not mandatory, 24/7 shifts and rotational week offs (5 days working a week), Immediate joiners only, Out of station candidates are strictly not eligible', 
        'https://www.naukri.com/job-listings-hiring-freshers-experience-for-international-voice-process-hyderabad-sutherland-hyderabad-1-to-3-years-110924019859?utmcampaign=androidjd&utmsource=share&src=sharedjd', 
        'https://instagram.com/job5', 
        'https://youtube.com/job5', 
        'https://pbs.twimg.com/media/FNVOGCyacAAuQem.jpg'),

        ('Hiring Email & Chat Support', 
        'HCL Tech Walk-In Drive 2024, Any Degree, Basic understanding of HTML, JavaScript & CSS, Knowledge of technical troubleshooting, Strong analytical skills, Willingness to work in night shifts, Good computer navigation skills', 
        'https://www.naukri.com/job-listings-hcltech-walk-in-drive-email-chat-support-14th-15th-sep-hyderabad-hcltech-hyderabad-1-to-5-years-110924020680?utmcampaign=androidjd&utmsource=share&src=sharedjd', 
        'https://instagram.com/job6', 
        'https://youtube.com/job6', 
        'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSt1VGT9Q_oR45MkKkJJTYd1vuxacMtSmZf1BLACRNwH38V6Okh1lc8Nh3vI1ZIa4jh9aU&usqp=CAU'),

        ('Data Engineer', 
        'Bachelors degree in computer science or related field, Excellent communication and team collaboration skills, Should have experience in Data and Analytics and overseen end-to-end implementation of data pipelines on cloud-based data platforms, Strong programming skills in Python, PySpark and some combination of Java, Scala (good to have), Experience writing SQL, Structuring data, and data storage practices, Experience in PySpark for Data Processing and transformation, Experience building stream-processing applications (Spark Streaming, Apache Flink, Kafka, etc.), Debug and upgrade existing systems, Nice to have some knowledge in DevOps, Work Location: Bangalore', 
        'https://ejgk.fa.em2.oraclecloud.com/hcmUI/CandidateExperience/en/sites/CX_1/job/INTG10019786/apply/email', 
        'https://instagram.com/job7', 
        'https://youtube.com/job7', 
        'https://i0.wp.com/opportunitycell.com/wp-content/uploads/2022/12/KPMG-London.png?fit=1000%2C667&ssl=1'),

        ('Data Engineer II', 
        'Bachelors degree in Computer Science or related technical field or equivalent practical experience, Experience coding using general purpose programming languages (e.g., Java, Python, Go, JavaScript, Fusion), Understanding and exposure to data tech stack e.g., Spark, Hive, Strong desire to learn and grow while building outstanding systems, Coding chops, clean, elegant, bug-free code in languages like JS, React, Node.js, open to new stacks as needed, Ability to identify and resolve performance and scalability issues, Work Location: Bangalore',  
        'https://www.uber.com/careers/apply/interstitial/133571?uclick_id=e180fbe2-4219-4b03-bf9d-9358d3cddb84', 
        'https://instagram.com/job8', 
        'https://youtube.com/job8', 
        'https://img.etimg.com/thumb/width-1200,height-1200,imgsize-40032,resizemode-75,msid-105470730/tech/technology/uber-rolls-out-rewards-programme-uber-pro-for-drivers-in-12-cities.jpg'),

        ('Python Developer - Intern', 
        'Students pursuing a degree or recent graduates in Computer Science, Information Technology, or a related field, Aspiring Python developers with a strong interest in software development, Analytical thinkers adept at solving complex programming challenges, Effective communicators who thrive in collaborative team environments, Enthusiastic learners committed to refining their Python development skills, Proficiency in Python programming language and related technologies (e.g., Django, Flask) is highly valued, Familiarity with software development lifecycle and best practices advantageous, Work Location: Hyderabad', 
        'https://kreativstorm.zohorecruit.eu/jobs/Careers/69764000051925815', 
        'https://instagram.com/job9', 
        'https://youtube.com/job9', 
        'https://kreativstorm.zohorecruit.eu/recruit/viewCareerImage.do?page_id=69764000000401668&type=logo&file_name=256x256_transparent.png'),

        ('Technical Support Engineer', 
        'Basic understanding of networking concepts (TCP/IP, UDP, DNS, NAT, gateways, etc.), Excellent time management skills with the ability to adapt to changing priorities of customer issues, Outstanding interpersonal skills and excellent communication, Develop and maintain a deep understanding of the Splunk product and related technologies, with a focus on our core platform, Drive continuous improvement of tools, processes, and product supportability, Work Location: Hyderabad, India', 
        'https://www.splunk.com/en_us/careers/jobs/technical-support-engineer-cloud-30829', 
        'https://instagram.com/job10', 
        'https://youtube.com/job10', 
        'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQSBLLLkyDaLgoJoJQMyzuwPUsTt1sW5kTaow&s');

      `);
    }

    app.listen(3000, () => {
      console.log("Server is running on http://localhost:3000/");
    });

  } catch (error) {
    console.error(`Error initializing the database: ${error.message}`);
    process.exit(1); // Exit the process with an error code
  }
};

initializeDbAndServer();

// Route to get all jobs
app.get("/api/jobs", async (req, res) => {
  try {
    const getAllJobsQuery = `SELECT * FROM job;`;
    const jobs = await database.all(getAllJobsQuery);

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

// Route to add a new job (including image_link)
app.post("/api/jobs", async (req, res) => {
  const { title, description, apply_link, instagram_link, youtube_link, image_link } = req.body;

  // Ensure all fields are provided
  if (!title || !description || !apply_link || !instagram_link || !youtube_link || !image_link) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const addJobQuery = `
      INSERT INTO job (title, description, apply_link, instagram_link, youtube_link, image_link)
      VALUES (?, ?, ?, ?, ?, ?);
    `;
    await database.run(addJobQuery, [title, description, apply_link, instagram_link, youtube_link, image_link]);
    res.status(201).json({ message: "Job added successfully" });
  } catch (error) {
    console.error(`Error adding job: ${error.message}`);
    res.status(500).json({ error: "Failed to add job" });
  }
});

// Root route
app.get("/", (req, res) => {
  res.send("Welcome to the Job Card Details API!");
});
