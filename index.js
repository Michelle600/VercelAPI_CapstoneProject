let express = require("express");
let path = require("path");
const cors = require("cors");
const { Pool } = require("pg");
require("dotenv").config();
const { DATABASE_URL, SECRET_KEY } = process.env;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { title } = require("process");

let app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        require: true,
        rejectUnauthorized: false,
    },
});


// Signup endpoint
app.post("/signup", async (req, res) => {
    const client = await pool.connect();

    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res
                .status(400)
                .json({ message: "Username and password are required." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const userResult = await client.query(
            "SELECT * FROM users WHERE username = $1",
            [username],
        );

        if (userResult.rows.length > 0) {
            return res.status(400).json({ message: "Username already taken." });
        }

        await client.query(
            "INSERT INTO users (username, password) VALUES ($1, $2)",
            [username, hashedPassword],
        );
        res.status(201).json({ message: "User registered successfully." });
    } catch (error) {
        console.error("Error:", error.message);
        res.status(500).json({ error: "Internal Server Error" });
    } finally {
        client.release();
    }
});

// Login endpoint
app.post("/login", async (req, res) => {
    const client = await pool.connect();
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res
                .status(400)
                .json({ message: "Username and password are required." });
        }

        const result = await client.query(
            "SELECT * FROM users WHERE username = $1",
            [username],
        );
        const user = result.rows[0];

        if (!user)
            return res
                .status(400)
                .json({ message: "Username or password incorrect" });

        const passwordIsValid = await bcrypt.compare(password, user.password);
        if (!passwordIsValid)
            return res.status(401).json({ auth: false, token: null });

        const token = jwt.sign(
            { id: user.id, username: user.username, userFirebaseID: user.firebase_id },
            SECRET_KEY,
            { expiresIn: 86400 },
        );
        res.status(200).json({ auth: true, token });
    } catch (error) {
        console.error("Error:", error.message);
        res.status(500).json({ error: "Internal Server Error" });
    } finally {
        client.release();
    }
});


// POST - Create expenses
app.post("/expenses", async (req, res) => {
    const client = await pool.connect();

    try {
        const token = req.headers["authorization"]?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ message: "Authorization token is required." });
        }

        const decoded = jwt.verify(token, SECRET_KEY);

        const userQuery = "SELECT firebase_id FROM users WHERE id = $1";
        const userResult = await client.query(userQuery, [decoded.id]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "User not found." });
        }

        const userFirebaseID = userResult.rows[0].firebase_id;

        const { title, amount, date, imageUrl } = req.body;
        if (!title || !amount || !date) {
            return res.status(400).json({ message: "Title, amount, and date are required." });
        }

        const query = `
            INSERT INTO expenses (userFirebaseID, title, amount, date, imageUrl)
            VALUES ($1, $2, $3, $4, $5) RETURNING id
        `;
        const params = [userFirebaseID, title, amount, date, imageUrl];

        const result = await client.query(query, params);
        const expenseID = result.rows[0].id;

        res.status(201).json({
            status: "success",
            data: { id: expenseID, userFirebaseID, title, amount, date, imageUrl },
            message: "Expense created successfully"
        });
    } catch (error) {
        console.error("Error creating expense:", error);
        res.status(500).json({ error: "Internal Server Error" });
    } finally {
        client.release();
    }
});



// GET - Read expenses
app.get("/expenses", async (req, res) => {
    const client = await pool.connect();

    try {

        const token = req.headers["authorization"]?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ message: "Authorization token is required." });
        }


        const decoded = jwt.verify(token, SECRET_KEY);


        const userQuery = "SELECT firebase_id FROM users WHERE id = $1";
        const userResult = await client.query(userQuery, [decoded.id]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "User not found." });
        }

        const userFirebaseID = userResult.rows[0].firebase_id;

        const expensesQuery = "SELECT * FROM expenses WHERE userFirebaseID = $1";
        const expensesResult = await client.query(expensesQuery, [userFirebaseID]);

        res.status(200).json(expensesResult.rows);
    } catch (error) {
        console.error("Error fetching expenses:", error);
        res.status(500).json({ error: "Internal Server Error" });
    } finally {
        client.release();
    }
});


// PUT - Update expenses
app.put("/expenses/:id", async (req, res) => {
    const client = await pool.connect();

    try {
        const token = req.headers["authorization"]?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ message: "Authorization token is required." });
        }

        const decoded = jwt.verify(token, SECRET_KEY);

        const userQuery = "SELECT firebase_id FROM users WHERE id = $1";
        const userResult = await client.query(userQuery, [decoded.id]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "User not found." });
        }

        const userFirebaseID = userResult.rows[0].firebase_id;

        const { id } = req.params;
        const { title, amount, date, imageUrl } = req.body;

        if (!title || !amount || !date) {
            return res.status(400).json({ message: "Title, amount, and date are required." });
        }

        const query = `
            UPDATE expenses 
            SET title = $1, amount = $2, date = $3, imageUrl = $4
            WHERE id = $5 AND userFirebaseID = $6
        `;
        const params = [title, amount, date, imageUrl, id, userFirebaseID];

        await client.query(query, params);

        res.status(200).json({
            status: "success",
            message: "Expense updated successfully"
        });
    } catch (error) {
        console.error("Error updating expense:", error);
        res.status(500).json({ error: "Internal Server Error" });
    } finally {
        client.release();
    }
});


// delete - Delete expenses
app.delete("/expenses/:id", async (req, res) => {
    const client = await pool.connect();

    try {
        const token = req.headers["authorization"]?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ message: "Authorization token is required." });
        }

        const decoded = jwt.verify(token, SECRET_KEY);

        const userQuery = "SELECT firebase_id FROM users WHERE id = $1";
        const userResult = await client.query(userQuery, [decoded.id]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "User not found." });
        }

        const userFirebaseID = userResult.rows[0].firebase_id;
        const { id } = req.params;

        const deleteQuery = `
            DELETE FROM expenses 
            WHERE id = $1 AND userFirebaseID = $2
        `;
        const deleteResult = await client.query(deleteQuery, [id, userFirebaseID]);

        if (deleteResult.rowCount === 0) {
            return res.status(404).json({ message: "Expense not found or not authorized to delete." });
        }

        res.json({
            status: "success",
            message: "Expense deleted successfully",
        });
    } catch (error) {
        console.error("Error deleting expense:", error.message);
        res.status(500).json({ error: "Internal Server Error" });
    } finally {
        client.release();
    }
});



app.get("/", (req, res) => {
    res.send("Welcome to Capstone Project API");
});

app.listen(3000, () => {
    console.log("App is listening on port 3000");
});
