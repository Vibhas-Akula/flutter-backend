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
    assignedTherapistId: {
        type: String,
        default: "THE12345" // temporary default
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
    therapistName: { type: String, required: true },
    password: { type: String, required: true }
}, { timestamps: true });

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

/* ================== MODELS ================== */

const Login = mongoose.model("Login", loginSchema);
const UserDetails = mongoose.model("UserDetails", userSchema);
const Documents = mongoose.model("Documents", documentSchema);
const Therapist = mongoose.model("Therapist", therapistSchema);
const Appointment = mongoose.model("Appointment", appointmentSchema);

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

        return res.status(401).json({
            success: false,
            message: "Token required"
        });

    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: "Invalid token"
            });
        }
        req.user = user;
        next();
    });
}

/* ================== ROUTES ================== */


/* ---------- REGISTER ---------- */

app.post("/register", upload.single("idDoc"), async (req, res) => {
    try {
        const { email, password, name, dob, gender, problem } = req.body;
        if (!password) {
            return res.status(400).json({
                success: false,
                message: "Password required"
            });
        }

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
            message: "User registered successfully",
            patientId
        });

    } catch (err) {

        console.error(err);
        res.status(500).json({
            success: false,
            message: "Server error"
        });

    }

});


/* ---------- LOGIN ---------- */

app.post("/login", async (req, res) => {

    try {

        const { patientId, password } = req.body;

        if (!patientId || !password) {

            return res.status(400).json({
                success: false,
                message: "Patient ID and password required"
            });

        }

        const login = await Login.findOne({ patientId });

        if (!login) {

            return res.status(401).json({
                success: false,
                message: "Invalid credentials"
            });

        }

        const valid = await argon2.verify(login.password, password);

        if (!valid) {

            return res.status(401).json({
                success: false,
                message: "Invalid credentials"
            });

        }

        const token = jwt.sign(
            {
                id: login._id,
                patientId: login.patientId
            },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            success: true,
            message: "Login successful",
            patientId: login.patientId,
            token
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            success: false,
            message: "Server error"
        });

    }

});


/* ---------- PROFILE ---------- */

app.get("/profile", authenticateToken, async (req, res) => {

    try {

        const profile = await UserDetails.findOne({
            loginId: req.user.id
        });

        const docs = await Documents.find({
            userId: req.user.id
        });

        res.json({
            success: true,
            profile,
            documents: docs
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            success: false,
            message: "Server error"
        });

    }

});


/* ---------- GET THERAPISTS ---------- */
app.post("/create-therapist", async (req, res) => {
    try {
        const { name, password } = req.body;

        const hashedPassword = await argon2.hash(password);

        const therapist = await Therapist.create({
            therapistId: generateTherapistId(),
            name,
            password: hashedPassword
        });

        res.json({
            success: true,
            therapist
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});

app.get("/my-therapist", authenticateToken, async (req, res) => {
    try {
        const user = await UserDetails.findOne({ loginId: req.user.id });

        const therapist = await Therapist.findOne({
            therapistId: user.assignedTherapistId
        });

        res.json({
            success: true,
            therapistId: therapist.therapistId,
            name: therapist.name
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});

/* ---------- BOOK APPOINTMENT ---------- */

app.post("/appointment", authenticateToken, async (req, res) => {

    try {

        const { therapistId, timeSlot } = req.body;

        if (!therapistId || !timeSlot) {

            return res.status(400).json({
                success: false,
                message: "Therapist ID and time slot required"
            });

        }

        const therapist = await Therapist.findOne({ therapistId });

        if (!therapist) {

            return res.status(404).json({
                success: false,
                message: "Therapist not found"
            });

        }

        const slotDate = new Date(timeSlot);

        if (slotDate <= new Date()) {

            return res.status(400).json({
                success: false,
                message: "Appointment date must be in the future"
            });

        }

        const conflict = await Appointment.findOne({
            therapistId: therapist._id,
            timeSlot: slotDate
        });

        if (conflict) {

            return res.status(409).json({
                success: false,
                message: "This slot is already booked. Please select a different time."
            });

        }

        const appointment = await Appointment.create({
            therapistId: therapist._id,
            patientId: req.user.id,
            timeSlot: slotDate
        });

        res.status(201).json({
            success: true,
            message: "Appointment booked successfully",
            appointment
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            success: false,
            message: "Server error"
        });

    }

});


/* ================== SERVER START ================== */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});