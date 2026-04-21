/* ================== DNS FIX ================== */
const dns = require("dns");
dns.setServers(["8.8.8.8"]);

/* ================== IMPORTS ================== */
require("dotenv").config();
const jwt = require("jsonwebtoken");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const argon2 = require("argon2");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const streamifier = require("streamifier");
const { customAlphabet } = require("nanoid");

const numericId = customAlphabet("0123456789", 5);

const app = express();

/* ================== MIDDLEWARE ================== */
app.use(cors());
app.use(express.json());

/* ================== CLOUDINARY ================== */
cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.API_KEY,
    api_secret: process.env.API_SECRET,
});

/* ================== DB ================== */
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("✅ MongoDB Connected"))
.catch(err => console.error(err));

/* ================== HELPERS ================== */
const generatePatientId = () => "PAT" + numericId();
const generateTherapistId = () => "THE" + numericId();
const generateSupervisorId = () => "SUP" + numericId();

/* ================== SCHEMAS ================== */

const loginSchema = new mongoose.Schema({
    patientId: { type: String, unique: true },
    password: String
});

const therapistSchema = new mongoose.Schema({
    therapistId: { type: String, unique: true },
    name: String,
    password: String
});

const supervisorSchema = new mongoose.Schema({
    supervisorId: { type: String, unique: true },
    name: String,
    password: String
});

/* ================== MODELS ================== */

const Login = mongoose.model("Login", loginSchema);
const Therapist = mongoose.model("Therapist", therapistSchema);
const Supervisor = mongoose.model("Supervisor", supervisorSchema);

/* ================== AUTH ================== */

function authenticateToken(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ success: false });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false });
        req.user = user;
        next();
    });
}

/* ================== CREATE USERS ================== */

app.post("/create-therapist", async (req, res) => {
    const { name, password } = req.body;

    const hashed = await argon2.hash(password);

    const therapist = await Therapist.create({
        therapistId: generateTherapistId(),
        name,
        password: hashed
    });

    res.json({ success: true, therapist });
});

app.post("/create-supervisor", async (req, res) => {
    const { name, password } = req.body;

    const hashed = await argon2.hash(password);

    const supervisor = await Supervisor.create({
        supervisorId: generateSupervisorId(),
        name,
        password: hashed
    });

    res.json({ success: true, supervisor });
});

app.post("/register", async (req, res) => {
    const { password } = req.body;

    const hashed = await argon2.hash(password);

    const user = await Login.create({
        patientId: generatePatientId(),
        password: hashed
    });

    res.json({ success: true, user });
});

/* ================== LOGIN ================== */

app.post("/login", async (req, res) => {
    try {
        const { patientId, password } = req.body;

        if (!patientId || !password) {
            return res.status(400).json({ success: false });
        }

        // PATIENT
        if (patientId.startsWith("PAT")) {
            const user = await Login.findOne({ patientId });

            if (!user || !(await argon2.verify(user.password, password))) {
                return res.status(401).json({ success: false });
            }

            const token = jwt.sign(
                { id: user._id, role: "patient" },
                process.env.JWT_SECRET
            );

            return res.json({ success: true, role: "patient", token });
        }

        // THERAPIST
        if (patientId.startsWith("THE")) {
            const therapist = await Therapist.findOne({ therapistId: patientId });

            if (!therapist || !(await argon2.verify(therapist.password, password))) {
                return res.status(401).json({ success: false });
            }

            const token = jwt.sign(
                { id: therapist._id, role: "therapist" },
                process.env.JWT_SECRET
            );

            return res.json({ success: true, role: "therapist", token });
        }

        // SUPERVISOR
        if (patientId.startsWith("SUP")) {
            const supervisor = await Supervisor.findOne({ supervisorId: patientId });

            if (!supervisor || !(await argon2.verify(supervisor.password, password))) {
                return res.status(401).json({ success: false });
            }

            const token = jwt.sign(
                { id: supervisor._id, role: "supervisor" },
                process.env.JWT_SECRET
            );

            return res.json({ success: true, role: "supervisor", token });
        }

        res.status(400).json({ success: false });

    } catch (err) {
        res.status(500).json({ success: false });
    }
});

/* ================== START ================== */
app.listen(3000, () => console.log("🚀 Server running on 3000"));