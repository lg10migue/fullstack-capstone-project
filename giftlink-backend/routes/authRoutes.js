const express = require("express");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const connectToDatabase = require("../models/db");
const router = express.Router();
const dotenv = require("dotenv");
const pino = require("pino");

// Create a Pino logger instance.
const logger = pino();

dotenv.config();

// Create JWT secret.
const JWT_SECRET = process.env.JWT_SECRET;

router.post("/register", async (req, res) => {
    try {
        // Task 1: Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`.
        const db = await connectToDatabase();

        // Task 2: Access MongoDB collection.
        const collection = db.collection("users");

        //Task 3: Check for existing email.
        const existingEmail = await collection.findOne({
            email: req.body.email,
        });

        if (existingEmail) {
            logger.error("Email already exists");
            return res.status(400).json({ error: "Email already exists" });
        }

        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        const email = req.body.email;

        // Task 4: Save user details in database.
        const newUser = await collection.insertOne({
            email: email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });

        //Task 5: Create JWT authentication with user._id as payload.
        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };

        const authToken = jwt.sign(payload, JWT_SECRET);
        logger.info("User registered successfully");
        res.json({ authToken, email });
    } catch (e) {
        return res.status(500).send("Internal server error");
    }
});

router.post("/login", async (req, res) => {
    console.log("\n\n Inside login");

    try {
        // Task 1: Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`.
        const db = await connectToDatabase();

        // Task 2: Access MongoDB `users` collection.
        const collection = db.collection("users");

        // Task 3: Check for user credentials in database.
        const user = await collection.findOne({ email: req.body.email });

        // Task 4: Task 4: Check if the password matches the encrypted password and send appropriate message on mismatch.
        if (user) {
            let result = await bcryptjs.compare(
                req.body.password,
                user.password
            );
            if (!result) {
                logger.error("Passwords do not match");
                return res.status(404).json({ error: "Wrong password" });
            }

            let payload = { user: { id: user._id.toString() } };

            // Task 5: Fetch user details from database.
            const userName = user.firstName;
            const userEmail = user.email;

            // Task 6: Create JWT authentication if passwords match with user._id as payload.
            const authToken = jwt.sign(payload, JWT_SECRET);
            logger.info("User logged in successfully");
            return res.status(200).json({ authToken, userName, userEmail });
        } else {
            // Task 7: Send appropriate message if user not found.
            logger.error("User not found");
            return res.status(404).json({ error: "User not found" });
        }
    } catch (e) {
        logger.error(e);
        return res
            .status(500)
            .json({ error: "Internal server error", details: e.message });
    }
});

module.exports = router;
