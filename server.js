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

/* ================== CLOUDINARY CONFIG ================== */
cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.API_KEY,
    api_secret: process.env.API_SECRET,
});

/* ================== MONGODB CONNECTION ================== */
mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected"))
    .catch((err) => console.error("❌ DB Connection Error:", err));

mongoose.connection.on("error", (err) => {
    console.error("MongoDB runtime error:", err);
});

/* ================== SCHEMAS ================== */

const loginSchema = new mongoose.Schema({
    patientId: { type: String, unique: true, required: true },
    password: { type: String, required: true },
}, { timestamps: true });

const userSchema = new mongoose.Schema({
    loginId: { type: mongoose.Schema.Types.ObjectId, ref: 'Login', required: true },
    therapistId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Therapist",
        default: new mongoose.Types.ObjectId("69e6695baafb8c422ff5d60f")
    },
    name: String,
    email: String,
    dob: Date,
    gender: String,
    problem: String
}, { timestamps: true });

const documentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Login', required: true },
    docType: String,
    url: String
}, { timestamps: true });

const therapistSchema = new mongoose.Schema({
    therapistId: { type: String, unique: true, required: true },
    name: { type: String, required: true },
    password: { type: String, required: true }
}, { timestamps: true });

/* ===== NEW SUPERVISOR ===== */
const supervisorSchema = new mongoose.Schema({
    supervisorId: { type: String, unique: true, required: true },
    name: { type: String, required: true },
    password: { type: String, required: true }
}, { timestamps: true });

/* ===== NEW REPORT ===== */
const reportSchema = new mongoose.Schema({
    patientId: String,
    therapistId: String,
    supervisorId: String,
    reportUrl: String,
    fileType: String,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const appointmentSchema = new mongoose.Schema({
    therapistId: { type: mongoose.Schema.Types.ObjectId, ref: 'Therapist', required: true },
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: 'Login', required: true },
    date: { type: Date, required: true },
    timeSlot: { type: String, required: true },
}, { timestamps: true });

/* ================== ID GENERATORS ================== */

function generatePatientId() {
    return "PAT" + numericId();
}

function generateTherapistId() {
    return "THE" + numericId();
}

function generateSupervisorId() {
    return "SUP" + numericId();
}

/* ================== MODELS ================== */

const Login = mongoose.model("Login", loginSchema);
const UserDetails = mongoose.model("UserDetails", userSchema);
const Documents = mongoose.model("Documents", documentSchema);
const Therapist = mongoose.model("Therapist", therapistSchema);
const Supervisor = mongoose.model("Supervisor", supervisorSchema);
const Report = mongoose.model("Report", reportSchema);
const Appointment = mongoose.model("Appointments", appointmentSchema);

/* ================== MULTER ================== */

const upload = multer({
    storage: multer.memoryStorage()
});

/* ================== CLOUDINARY HELPER ================== */

const uploadToCloudinary = (buffer) => {
    return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
            { resource_type: "auto" },
            (error, result) => {
                if (error) reject(error);
                else resolve(result);
            }
        );
        streamifier.createReadStream(buffer).pipe(stream);
    });
};

/* ================== AUTH MIDDLEWARE ================== */

function authenticateToken(req, res, next) {

    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ success: false, message: "Token required" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: "Invalid token" });
        }
        req.user = user;
        next();
    });
}

/* ================== REGISTER (UNCHANGED) ================== */

app.post("/register", upload.single("idDoc"), async (req, res) => {
    try {
        const { email, password, name, dob, gender, problem } = req.body;

        const hashedPassword = await argon2.hash(password);
        const patientId = generatePatientId();

        const login = await Login.create({
            patientId,
            password: hashedPassword
        });

        await UserDetails.create({
            loginId: login._id,
            name,
            email,
            dob,
            gender,
            problem
        });

        if (req.file) {
            const result = await uploadToCloudinary(req.file.buffer);
            await Documents.create({
                userId: login._id,
                docType: "ID Proof",
                url: result.secure_url
            });
        }

        res.status(201).json({
            success: true,
            patientId
        });

    } catch (err) {
        res.status(500).json({ success: false });
    }
});

/* ================== LOGIN (UPDATED FOR ALL ROLES) ================== */

app.post("/login", async (req, res) => {
    try {
        const { patientId, password } = req.body;

        /* PATIENT */
        if (patientId.startsWith("PAT")) {
            const login = await Login.findOne({ patientId });

            if (!login || !(await argon2.verify(login.password, password))) {
                return res.status(401).json({ success: false });
            }

            const token = jwt.sign(
                { id: login._id, role: "patient", patientId: login.patientId },
                process.env.JWT_SECRET,
                { expiresIn: "7d" }
            );

            return res.json({ success: true, role: "patient", token });
        }

        /* THERAPIST */
        if (patientId.startsWith("THE")) {
            const therapist = await Therapist.findOne({ therapistId: patientId });

            if (!therapist || !(await argon2.verify(therapist.password, password))) {
                return res.status(401).json({ success: false });
            }

            const token = jwt.sign(
                { id: therapist.therapistId, role: "therapist" },
                process.env.JWT_SECRET
            );

            return res.json({ success: true, role: "therapist", token });
        }

        /* SUPERVISOR */
        if (patientId.startsWith("SUP")) {
            const supervisor = await Supervisor.findOne({ supervisorId: patientId });

            if (!supervisor || !(await argon2.verify(supervisor.password, password))) {
                return res.status(401).json({ success: false });
            }

            const token = jwt.sign(
                { id: supervisor.supervisorId, role: "supervisor" },
                process.env.JWT_SECRET
            );

            return res.json({ success: true, role: "supervisor", token });
        }

        res.status(400).json({ success: false });

    } catch (err) {
        res.status(500).json({ success: false });
    }
});

/* ================== CREATE THERAPIST ================== */

app.post("/create-therapist", async (req, res) => {
    const hashed = await argon2.hash(req.body.password);
    const therapist = await Therapist.create({
        therapistId: generateTherapistId(),
        name: req.body.name,
        password: hashed
    });
    res.json({ success: true, therapist });
});

/* ================== CREATE SUPERVISOR ================== */

app.post("/create-supervisor", async (req, res) => {
    const hashed = await argon2.hash(req.body.password);
    const supervisor = await Supervisor.create({
        supervisorId: generateSupervisorId(),
        name: req.body.name,
        password: hashed
    });
    res.json({ success: true, supervisor });
});

/* ================== SEND REPORT ================== */

app.post("/send-report", authenticateToken, upload.single("file"), async (req, res) => {

    if (req.user.role !== "therapist") {
        return res.status(403).json({ success: false });
    }

    const result = await uploadToCloudinary(req.file.buffer);

    const report = await Report.create({
        patientId: req.body.patientId,
        therapistId: req.user.id,
        supervisorId: req.body.supervisorId,
        reportUrl: result.secure_url,
        fileType: req.file.mimetype
    });

    res.json({ success: true, report });
});

/* ================== VIEW REPORTS ================== */

app.get("/reports", authenticateToken, async (req, res) => {

    if (req.user.role !== "supervisor") {
        return res.status(403).json({ success: false });
    }

    const reports = await Report.find({
        supervisorId: req.user.id
    }).sort({ createdAt: -1 });

    res.json({ success: true, reports });
});

/* ================== PROFILE (UNCHANGED) ================== */

app.get("/profile", authenticateToken, async (req, res) => {
    const profile = await UserDetails.findOne({ loginId: req.user.id });
    const docs = await Documents.find({ userId: req.user.id });

    res.json({ success: true, profile, documents: docs });
});

/* ================== APPOINTMENT (UNCHANGED) ================== */

app.post("/appointment", authenticateToken, async (req, res) => {

    const { date, timeSlot } = req.body;

    const user = await UserDetails.findOne({ loginId: req.user.id });

    const conflict = await Appointment.findOne({
        therapistId: user.therapistId,
        date,
        timeSlot
    });

    if (conflict) {
        return res.status(409).json({ success: false });
    }

    const appointment = await Appointment.create({
        therapistId: user.therapistId,
        patientId: req.user.id,
        date,
        timeSlot
    });

    res.json({ success: true, appointment });
});

/* ================== SERVER ================== */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("🚀 Server running on port", PORT);
});