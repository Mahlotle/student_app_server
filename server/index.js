import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import jwt from 'jsonwebtoken'; // For token-based authentication
import bcrypt from 'bcrypt'; // For password hashing
import cookieParser from 'cookie-parser'; // For parsing cookies

import dotenv from 'dotenv';
dotenv.config();

// Database
import pkg from 'pg';
const { Client } = pkg;

const app = express();

// Middleware setup
app.use(express.json()); 
app.use(cors({
    origin: "http://localhost:5173", // Ensure this matches the frontend origin
    methods: ["POST", "GET"],
    credentials: true
}));
app.use(cookieParser());

// DB CONNECTION Local
// const db = mysql.createConnection({
//     host: process.env.DB_HOST,
//     user: process.env.DB_USER,
//     password: process.env.DB_PASSWORD,
//     database: process.env.DB_DATABASE
// });

// add this for testing


// DB Config for hosting
const db = new Client({
    host: process.env.PGHOST,
    port: process.env.PGPORT,
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    database: process.env.PGDATABASE
});

// Connect to the database
db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Connected to database.');
});

// Middleware to verify user authentication
const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are not Authenticated" });
    }
    
    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
        if (err) {
            return res.json({ Error: "Token not verified" });
        } else {
            req.name = decoded.name; // Use FName as `name` in the payload
            next();
        }
    });
}

// Route to check authentication and get user name
app.get('/', verifyUser, (req, res) => {
    return res.json({ Status: "Success", name: req.name }); // Send `name` as response
})

// Register route for handling user sign-up
app.post('/register', (req, res) => {
    const { FName, LName, email, password } = req.body;

    // Check if email already exists
    const checkEmailSql = 'SELECT * FROM register WHERE email = ?';
    db.query(checkEmailSql, [email], (err, data) => {
        if (err) {
            return res.json({ Error: "Error checking email in server" });
        }

        if (data.length > 0) {
            return res.json({ Error: "Email already exists." });
        }

        // Password hashing
        bcrypt.hash(password.toString(), 10, (err, hash) => {
            if (err) {
                return res.json({ Error: "Error hashing password" });
            }

            // Prepare the values to be inserted into the database
            const insertSql = "INSERT INTO register (FName, LName, email, password) VALUES (?)";
            const values = [
                FName,
                LName,
                email,
                hash // Store the hashed password
            ];

            // Execute the SQL query to insert the new user into the database
            db.query(insertSql, [values], (error, result) => {
                if (error) {
                    return res.json({ Error: "Error inserting data into server" });
                }
                // Successfully inserted the new user
                return res.json({ Status: "Success" });
            });
        });
    });
});

// Login route for handling user login
app.post('/login', (req, res) => {
    const sql = 'SELECT * FROM register WHERE email = ?';

    // Execute the SQL query to find the user
    db.query(sql, [req.body.email], (err, data) => {
        if (err) {
            return res.json({ Error: "Error fetching data from server" });
        }

        if (data.length > 0) {
            // If a user with the provided email exists, compare passwords
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if (err) {
                    return res.json({ Error: "Error comparing passwords" });
                }
                if (response) {
                    const name = data[0].FName; // Use FName from the database
                    const token = jwt.sign({ name }, "jwt-secret-key", { expiresIn: '1d' }); // Token expires in 1 day
                    res.cookie('token', token, { httpOnly: true }); // Set cookie with httpOnly flag for security
                    return res.json({ Status: "Success" });
                } else {
                    return res.json({ Error: "Incorrect Password" });
                }
            });
        } else {
            return res.json({ Error: "Email Not Registered" });
        }
    });
});

/*app.get('/logout', (req,res)=> {
    res.clearCookie('token');
    return res.json({Status: "Success"})
})*/
app.post('/logout', (req, res) => {
    res.clearCookie('token'); // Clear the token cookie
    res.json({ Status: "Success" });
  });
  

// Start the server
app.listen(8081, () => {
    console.log("Server running on port 8081...");
});
