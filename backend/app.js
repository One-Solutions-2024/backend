const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const cors = require("cors");
const helmet = require("helmet");
const { body, validationResult } = require("express-validator");
require("dotenv").config(); // Load environment variables
const PORT = process.env.PORT || 3000;


const databasePath = path.join(__dirname, process.env.DB_PATH || "jobs.db");

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet()); // Basic security headers


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
        companyname TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        apply_link TEXT NOT NULL,
        image_link TEXT NOT NULL
      );
    `);

    // Insert jobs if table is empty (including image links)
    const jobsCount = await database.get(`SELECT COUNT(*) as count FROM job;`);
    if (jobsCount.count === 0) {
      await database.run(`
        INSERT INTO job (companyname, title, description, apply_link, image_link) VALUES 
         ('Capgemini',
        'Software Engineer', 
        'BE/BTech/ ME/MTech / MCA & MSC, Freshers 2023 & 2024, Communication: You should possess strong communication skills for effective interactions with project partners., Collaboration: You should demonstrate good interpersonal and collaboration skills, Flexibility: You should be willing to skill-up in multiple technologies and work in any Capgemini city location and travel as required., Initiative: You should be able to work independently, take initiative and manage a variety of activities concurrently.,Other Skills: Good analytical and problem-solving skill.,Location: Mumbai, Pune, Bangalore', 
        'https://app.joinsuperset.com/join/#/signup/student/jobprofiles/6e4f8e33-c0a0-4348-83af-66cd8aa8ff9e', 
        'https://sightsinplus.com/wp-content/uploads/2022/08/Capgemini-India-is-hiring-across-the-country-check-details-here.jpg'),

         ('Simplotel Technologies',
        'Data Automation Analyst', 
        'Bachelor of Engineering required. MBA is a plus., 0-3 years of experience with scripts, data warehousing, and / or automation,  Hands-on experience (or proficiency with SQL and Python), Proficiency in data mining, mathematics, and statistical analysis, Keen attention to detail to ensure accuracy in data processing, analysis, and reporting , Strong analytical and problem-solving skills,Good communication and interpersonal skills.,Ability to work effectively within a team and collaborate with cross-functional departments,Experience in data reporting and proficiency in SQL are advantageous for querying and managing relational databases.,Location:Bangalore', 
        'https://app.joinsuperset.com/join/#/signup/student/jobprofiles/6e4f8e33-c0a0-4348-83af-66cd8aa8ff9e', 
        'https://ratetiger.com/wp-content/uploads/2021/07/simplotel-PR.jpg'),

        ('Genpact',
        'Technical Associate', 
        'BE/ BTech/ MCA, 2018/ 2019/ 2020/ 2021/ 2022/ 2023/ 2024, Experience with writing clean code in Java, Excellent oral and written communication skills  , Strong knowledge of technology security controls (Authentication, Authorization and Encryption of data, Single Sign On, Data retention/deletion etc.), Understanding of PII data and applicable controls to safeguard it., Good analytical skills , Proficient in PowerPoint and Excel', 
        'https://genpact.taleo.net/careersection/sgy_external_career_section/jobdetail.ftl?job=ITO083797', 
        'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTbaYaam0-ve4j-3cnccZ7akzMNwmGoF2e8NA&s'),

        
         ('Zebra',
        'SOFTWARE ENGINEER', 
        'BTech/ MTech, Freshers(0-2yrs), Establishes requirements for less complex design projects, Works on Completing all phases of Software engineering design projects, Works on analysis of processes and delivers results to necessary stakeholder, Strong Works with latest technologies and new approaches, Multi-threading, Multi process handling and Memory management., Work Location : Pune.', 
        'https://careers.zebra.com/careers/job/343622504714?domain=zebra.com', 
        'https://fortune.com/img-assets/wp-content/uploads/2024/05/GPTW-2024-Chicago-Large-Zebra-Technologies-Corporation_US1__20240410151431_4.jpg?w=1440&q=75'),

         ('Trimble',
        'Customer Support', 
        'Any Graduate, Freshers(0-1yrs), Process-oriented with high attention to detail, Basic knowledge of computer MS Windows & MS Office, Problem solving and analytical skills, Excellent written and verbal communication skills.,Basic knowledge of Google Workspace, Work Location : Chennai India.', 
        'https://careers.zebra.com/careers/job/343622504714?domain=zebra.com', 
        'https://bsmedia.business-standard.com/_media/bs/img/article/2022-03/30/full/20220330181036.jpg'),

       
        ('Cognizant',
        'Associate - Projects', 
        'Possess a strong background in SAP EWM Testing, Demonstrate specialized skills in EWM, Exhibit excellent problem-solving abilities, Show proficiency in developing test plans, Have experience in defect tracking and resolution, Display strong communication skills, Be familiar with industry standards, Mentor and guide junior team members, Work Location: Hybrid', 
        'https://cognizant.taleo.net/careersection/Lateral/jobapply.ftl?job=00060120911&lang=en&source=CWS-13082&src=CWS-13082', 
        'https://static.toiimg.com/thumb/msid-112500237,width-1280,height-720,resizemode-4/112500237.jpg'),

       
        ('Razor Infotech',
        'Python and MERN Stack developer', 
        'Bachelor’s degree in Computer Science Information Technology or a related field., 2 - 3 LPA, Minimum of 1 year of professional experience in Python programming., Hands-on experience with the MERN stack:, MongoDB: Proficient in database design and querying., Express.js: Experience in building RESTful APIs., React.js: Skilled in developing user interfaces and managing state., Node.js: Proficient in server-side scripting., Familiarity with front-end technologies such as HTML5, CSS3, and JavaScript., Experience with version control systems, particularly Git., Work Location: In Office Delhi', 
        'https://unstop.com/competitions/1164238/register', 
        'https://d8it4huxumps7.cloudfront.net/uploads/images/150x150/66ed1954a4079_organisation_image-UuScTTlJli1498478550WQzm7rzD0E.png?d=200x200'),
        
        ('Intelliworkz',
        'Fronted Developer', 
        'Bachelor’s degree in Computer Science Information Technology or a related field., Strong knowledge of HTML5 and CSS3 structure elements tags and attributes., Experience with media queries for responsiveness., Optimizing HTML code for search engines., Familiarity with basic JavaScript for adding interactive elements (drop-down menus, sliders, form validation)., Knowledge of JavaScript libraries like jQuery for easier DOM manipulation., Figma  to HTML design., Exp: 1 - 2 yrs,  Work Location: IAhmedabad', 
        'https://unstop.com/competitions/1163414/register', 
        'https://images.yourstory.com/cs/images/companies/404e7f741540-925D6B6558F2414F8714EB3C0A2C5973-1660197102039.jpg?fm=auto&ar=1:1&mode=fill&fill=solid&fill-color=fff'),
        
         ('Amazon',
        'Associate ', 
        'Any graduate., 2017-2018-2019-2020-2021-2022-2023-2024., Work Experience: 0 to 1 years., Communication Skills- Excellent communication skills (written and spoken) in English language., Ability to handle and interpret large sets of data, Work Location: WFH', 
        'https://amazonvirtualhiring.hirepro.in/registration/incta/ju0f4/apply/?j=58164&e=14190', 
        'https://media.istockphoto.com/id/1317474419/photo/amazon.jpg?s=612x612&w=0&k=20&c=XfMWt3qTPFbhq_82ZejFTryb_v-HXRNOqxPizblgLj0='),
        
         ('Ey',
        'Assurance - Associate', 
        ' B.com Graduates, 2021-2022-2023-2024, Work Experience: 0 to 1 years., Strong interpersonal and good written & oral communication skills., Robust logical and reasoning skills , Basis knowledge on MS – Excel Ms - Office,Interest in business and commerciality.,  Work Location: Noida', 
        'https://careers.ey.com/ey/job/Noida-Assurance-Associate-UP-201301/1120452901/', 
        'https://bsmedia.business-standard.com/_media/bs/img/article/2024-02/12/full/1707678091-5108.jpg?im=FitAndFill=(826,465)'),
       
        ('Kpmg',
        'QA Engineer', 
        'Bachelor’s degree or equivalent experience required, No prior experience required, Study or experience focused on one of the following or equivalent: quality engineering, quality systems, systems monitoring, computer systems management, Ability to clearly articulate ideas, such as current state and optimal state of a given system, Experience with test automation frameworks such as Selenium, Cypress, or Java tools preferred, Work Location: Bangalore', 
        'https://unstop.com/o/QYKRL4I?utm_medium=Share&utm_source=shortUrl', 
        'https://i0.wp.com/opportunitycell.com/wp-content/uploads/2022/12/KPMG-London.png?fit=1000%2C667&ssl=1'),

        ('Genpact',
        'Software Development Engineer', 
        'GE Digital Career 2024 Invites Students From Various Disciplines to apply for the Position of Software Development Engineer in Hyderabad, India, Freshers/Experienced, Bachelor’s Degree in Computer Science or “STEM” Majors (Science, Technology, Engineering and Math) with basic experience, Expertise in Java programming, particularly in Object-Oriented Programming (OOP) concepts, The ideal candidate should have a proven track record in implementing REST endpoints and a strong background in utilizing the Spring Boot framework, including Spring Security, Spring JPA, and Spring MVC, Proficient in front-end technologies like Angular, HTML5, and CSS, Write Unit Tests using JUnit for ensuring code quality and reliability, Experience with dependency management tools like Gradle or Maven for project build automation, Work on core data structures and algorithms and implement them using language of choice, Work Location: Hyderabad, India (Hybrid)', 
        'https://jobs.gecareers.com/global/en/apply?jobSeqNo=GE11GLOBALR3780300EXTERNALENGLOBAL&step=1&stepname=personalInformation', 
        'https://job4software.com/wp-content/uploads/2024/09/gettyimages-868982314-scaled.webp'),

        ('Genpact',
        'Device Associate', 
        'Graduate, preferably in a quantitative field of study with relevant experience of 0-1 years, Good communication skills, detail-oriented, and be a team player, Knowledge of QA methodology and tools, Gain understanding of the application test procedures and how to use applicable software and tools, Execute test instructions and report test results accurately and promptly, Report any deviations observed, Understand any changes in test instructions related to their assigned work', 
        'https://www.amazon.jobs/en/jobs/2769644/device-associate', 
        'https://etimg.etb2bimg.com/photo/91892300.cms'),

        ('Genpact',
        'International Voice Process-Hyderabad', 
        'Must be fluent in English, Excellent communication skills can apply, Both freshers and experienced candidates can apply, Graduation is not mandatory, 24/7 shifts and rotational week offs (5 days working a week), Immediate joiners only, Out of station candidates are strictly not eligible', 
        'https://www.naukri.com/job-listings-hiring-freshers-experience-for-international-voice-process-hyderabad-sutherland-hyderabad-1-to-3-years-110924019859?utmcampaign=androidjd&utmsource=share&src=sharedjd', 
        'https://pbs.twimg.com/media/FNVOGCyacAAuQem.jpg'),

        ('Genpact',
        'Hiring Email & Chat Support', 
        'HCL Tech Walk-In Drive 2024, Any Degree, Basic understanding of HTML, JavaScript & CSS, Knowledge of technical troubleshooting, Strong analytical skills, Willingness to work in night shifts, Good computer navigation skills', 
        'https://www.naukri.com/job-listings-hcltech-walk-in-drive-email-chat-support-14th-15th-sep-hyderabad-hcltech-hyderabad-1-to-5-years-110924020680?utmcampaign=androidjd&utmsource=share&src=sharedjd', 
        'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSt1VGT9Q_oR45MkKkJJTYd1vuxacMtSmZf1BLACRNwH38V6Okh1lc8Nh3vI1ZIa4jh9aU&usqp=CAU'),

        ('Genpact',
        'Data Engineer', 
        'Bachelors degree in computer science or related field, Excellent communication and team collaboration skills, Should have experience in Data and Analytics and overseen end-to-end implementation of data pipelines on cloud-based data platforms, Strong programming skills in Python, PySpark and some combination of Java, Scala (good to have), Experience writing SQL, Structuring data, and data storage practices, Experience in PySpark for Data Processing and transformation, Experience building stream-processing applications (Spark Streaming, Apache Flink, Kafka, etc.), Debug and upgrade existing systems, Nice to have some knowledge in DevOps, Work Location: Bangalore', 
        'https://ejgk.fa.em2.oraclecloud.com/hcmUI/CandidateExperience/en/sites/CX_1/job/INTG10019786/apply/email', 
        'https://i0.wp.com/opportunitycell.com/wp-content/uploads/2022/12/KPMG-London.png?fit=1000%2C667&ssl=1'),
       
        ('Genpact',
        'Data Engineer II', 
        'Bachelors degree in Computer Science or related technical field or equivalent practical experience, Experience coding using general purpose programming languages (e.g., Java, Python, Go, JavaScript, Fusion), Understanding and exposure to data tech stack e.g., Spark, Hive, Strong desire to learn and grow while building outstanding systems, Coding chops, clean, elegant, bug-free code in languages like JS, React, Node.js, open to new stacks as needed, Ability to identify and resolve performance and scalability issues, Work Location: Bangalore',  
        'https://www.uber.com/careers/apply/interstitial/133571?uclick_id=e180fbe2-4219-4b03-bf9d-9358d3cddb84', 
        'https://img.etimg.com/thumb/width-1200,height-1200,imgsize-40032,resizemode-75,msid-105470730/tech/technology/uber-rolls-out-rewards-programme-uber-pro-for-drivers-in-12-cities.jpg'),

        ('Genpact',
        'Python Developer - Intern', 
        'Students pursuing a degree or recent graduates in Computer Science, Information Technology, or a related field, Aspiring Python developers with a strong interest in software development, Analytical thinkers adept at solving complex programming challenges, Effective communicators who thrive in collaborative team environments, Enthusiastic learners committed to refining their Python development skills, Proficiency in Python programming language and related technologies (e.g., Django, Flask) is highly valued, Familiarity with software development lifecycle and best practices advantageous, Work Location: Hyderabad', 
        'https://kreativstorm.zohorecruit.eu/jobs/Careers/69764000051925815', 
        'https://kreativstorm.zohorecruit.eu/recruit/viewCareerImage.do?page_id=69764000000401668&type=logo&file_name=256x256_transparent.png'),

        ('Genpact',
        'Technical Support Engineer', 
        'Basic understanding of networking concepts (TCP/IP, UDP, DNS, NAT, gateways, etc.), Excellent time management skills with the ability to adapt to changing priorities of customer issues, Outstanding interpersonal skills and excellent communication, Develop and maintain a deep understanding of the Splunk product and related technologies, with a focus on our core platform, Drive continuous improvement of tools, processes, and product supportability, Work Location: Hyderabad, India', 
        'https://www.splunk.com/en_us/careers/jobs/technical-support-engineer-cloud-30829', 
        'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQSBLLLkyDaLgoJoJQMyzuwPUsTt1sW5kTaow&s');

      `);
    }

    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}/`);
    });

  } catch (error) {
    console.error(`Error initializing the database: ${error.message}`);
    process.exit(1); // Exit the process with an error code
  }
};

initializeDbAndServer();

// Route to get all jobs
app.get("/api/jobs", async (req, res) => {
  const { page = 1, limit = 10 } = req.query; // Pagination query params

  try {
    const offset = (page - 1) * parseInt(limit);
    const getAllJobsQuery = `
      SELECT * FROM job LIMIT ${limit} OFFSET ${offset};
    `;
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

// Route to update a job
app.put("/api/jobs/:id", async (req, res) => {
  const { id } = req.params;
  const {companyname, title, description, apply_link, image_link } = req.body;

  try {
    const updateJobQuery = `
      UPDATE job
      SET companyname = ?, title = ?, description = ?, apply_link = ?, image_link = ?
      WHERE id = ?;
    `;
    await database.run(updateJobQuery, [companyname, title, description, apply_link, image_link, id]);
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
    const deleteJobQuery = `DELETE FROM job WHERE id = ?;`;
    await database.run(deleteJobQuery, id);
    res.json({ message: "Job deleted successfully" });
  } catch (error) {
    console.error(`Error deleting job: ${error.message}`);
    res.status(500).json({ error: "Failed to delete job" });
  }
});



// Route to add a new job (including image_link)
app.post(
  "/api/jobs",
  [
      body("companyname").notEmpty(),
      body("title").notEmpty(),
      body("description").notEmpty(),
      body("apply_link").isURL(),
      body("image_link").isURL(),
  ],
  async (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { companyname, title, description, apply_link, image_link } = req.body;

      try {
          await database.run(`INSERT INTO job (companyname, title, description, apply_link, image_link) VALUES (?, ?, ?, ?, ?)`,
              [companyname, title, description, apply_link, image_link]);
          res.status(201).json({ message: "Job added successfully" });
      } catch (error) {
          console.error("Failed to add job:", error);
          res.status(500).json({ error: "Failed to add job" });
      }
  }
);

// Route to get job by company name
app.get("/api/jobs/company/:companyname", async (req, res) => {
  const { companyname } = req.params;

  try {
    const getJobByCompanyNameQuery = `
      SELECT * FROM job WHERE companyname = ?;
    `;
    const job = await database.get(getJobByCompanyNameQuery, [companyname]);

    if (job) {
      res.json(job);
    } else {
      res.status(404).json({ error: "Job not found" });
    }
  } catch (error) {
    console.error(`Error fetching job by company name: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve job" });
  }
});


// Root route
app.get("/", (req, res) => {
  res.send("Welcome to the Job Card Details API!");
});
