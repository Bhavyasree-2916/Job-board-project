require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

/* ===============================
   DATABASE CONNECTION
================================ */
mongoose.connect(process.env.MONGO_URI)
.then(()=> console.log("MongoDB Connected"))
.catch(err=> console.log(err));


/* ===============================
   SCHEMAS & MODELS
================================ */

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: {
    type: String,
    enum: ["candidate", "employer"],
    required: true
  },
  createdAt: { type: Date, default: Date.now }
});

const jobSchema = new mongoose.Schema({
  title: String,
  company: String,
  location: String,
  salary: Number,
  description: String,
  skills: [String],
  postedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },
  createdAt: { type: Date, default: Date.now }
});

const applicationSchema = new mongoose.Schema({
  jobId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Job"
  },
  candidateId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },
  resumeLink: String,
  coverLetter: String,
  status: {
    type: String,
    enum: ["applied", "shortlisted", "rejected"],
    default: "applied"
  },
  appliedAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Job = mongoose.model("Job", jobSchema);
const Application = mongoose.model("Application", applicationSchema);


/* ===============================
   AUTH MIDDLEWARE
================================ */

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token)
    return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};


/* ===============================
   REGISTER USER
================================ */

app.post("/api/auth/register", async (req, res) => {

  try {

    const { name, email, password, role } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      role
    });

    await user.save();

    res.json({ message: "User registered successfully" });

  } catch (err) {
    res.status(500).json(err);
  }

});


/* ===============================
   LOGIN USER
================================ */

app.post("/api/auth/login", async (req, res) => {

  try {

    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user)
      return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token });

  } catch (err) {
    res.status(500).json(err);
  }

});


/* ===============================
   CREATE JOB (EMPLOYER ONLY)
================================ */

app.post("/api/jobs", authMiddleware, async (req, res) => {

  if (req.user.role !== "employer")
    return res.status(403).json({ message: "Only employers can post jobs" });

  try {

    const job = new Job({
      ...req.body,
      postedBy: req.user.id
    });

    await job.save();

    res.json(job);

  } catch (err) {
    res.status(500).json(err);
  }

});


/* ===============================
   GET ALL JOBS
   SEARCH + PAGINATION
================================ */

app.get("/api/jobs", async (req, res) => {

  try {

    const { page = 1, limit = 5, search, location } = req.query;

    let query = {};

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { skills: { $regex: search, $options: "i" } }
      ];
    }

    if (location)
      query.location = location;

    const jobs = await Job.find(query)
      .populate("postedBy", "name email")
      .skip((page - 1) * limit)
      .limit(Number(limit));

    res.json(jobs);

  } catch (err) {
    res.status(500).json(err);
  }

});


/* ===============================
   GET JOB BY ID
================================ */

app.get("/api/jobs/:id", async (req, res) => {

  try {

    const job = await Job.findById(req.params.id)
      .populate("postedBy", "name email");

    res.json(job);

  } catch (err) {
    res.status(500).json(err);
  }

});


/* ===============================
   UPDATE JOB
================================ */

app.put("/api/jobs/:id", authMiddleware, async (req, res) => {

  try {

    const job = await Job.findById(req.params.id);

    if (!job)
      return res.status(404).json({ message: "Job not found" });

    if (job.postedBy.toString() !== req.user.id)
      return res.status(403).json({ message: "Not authorized" });

    const updatedJob = await Job.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    res.json(updatedJob);

  } catch (err) {
    res.status(500).json(err);
  }

});


/* ===============================
   DELETE JOB
================================ */

app.delete("/api/jobs/:id", authMiddleware, async (req, res) => {

  try {

    const job = await Job.findById(req.params.id);

    if (job.postedBy.toString() !== req.user.id)
      return res.status(403).json({ message: "Not authorized" });

    await job.deleteOne();

    res.json({ message: "Job deleted" });

  } catch (err) {
    res.status(500).json(err);
  }

});


/* ===============================
   APPLY FOR JOB (CANDIDATE)
================================ */

app.post("/api/applications/:jobId", authMiddleware, async (req, res) => {

  if (req.user.role !== "candidate")
    return res.status(403).json({ message: "Only candidates can apply" });

  try {

    const application = new Application({
      jobId: req.params.jobId,
      candidateId: req.user.id,
      resumeLink: req.body.resumeLink,
      coverLetter: req.body.coverLetter
    });

    await application.save();

    res.json(application);

  } catch (err) {
    res.status(500).json(err);
  }

});


/* ===============================
   VIEW JOB APPLICANTS
================================ */

app.get("/api/applications/job/:jobId", authMiddleware, async (req, res) => {

  try {

    const applications = await Application.find({
      jobId: req.params.jobId
    }).populate("candidateId", "name email");

    res.json(applications);

  } catch (err) {
    res.status(500).json(err);
  }

});


/* ===============================
   UPDATE APPLICATION STATUS
================================ */

app.put("/api/applications/:id/status", authMiddleware, async (req, res) => {

  try {

    const { status } = req.body;

    const application = await Application.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );

    res.json(application);

  } catch (err) {
    res.status(500).json(err);
  }

});


/* ===============================
   START SERVER
================================ */

app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});