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

        // Validate input data
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
            { id: user.id, username: user.username },
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

// post - Create expenses
app.post("/expenses", async (req, res) => {
    const client = await pool.connect();
    try {
        const data = {
            user_id: req.body.user_id,
            title: req.body.title,
            amount: req.body.amount,
            date: req.body.date,
            imageUrl: req.body.imageUrl,
        };
        const query =
            "INSERT INTO expenses (user_id, title, amount, date,imageUrl) VALUES ($1, $2, $3, $4, $5) RETURNING id";
        const params = [
            data.user_id,
            data.title,
            data.amount,
            data.date,
            data.imageUrl,
        ];

        const result = await client.query(query, params);
        data.id = result.rows[0].id;

        console.log(`Expenses created successfully with id ${data.id}`);
        res.json({
            status: "success",
            data: data,
            message: "Expenses created successfully",
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error });
    } finally {
        client.release();
    }
});

// get - Read expenses
app.get("/expenses", async (req, res) => {
    const client = await pool.connect();

    try {
        const query = "SELECT * FROM expenses";
        const result = await client.query(query);
        res.json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error });
    } finally {
        client.release();
    }
});

// put - Update expenses

app.put("/expenses/:id", async (req, res) => {
    const id = req.params.id;
    const updatedData = req.body;
    const client = await pool.connect();
    try {
        const updateQuery =
            "UPDATE expenses SET title = $1, amount = $2, date = $3, imageUrl = $4 WHERE id = $5";
        const queryData = [
            updatedData.title,
            updatedData.amount,
            updatedData.date,
            updatedData.imageUrl,
            id,
        ];

        await client.query(updateQuery, queryData);

        res.json({
            status: "success",
            message: "Expenses updated successfully",
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error });
    } finally {
        client.release();
    }
});

// delete - Delete expenses
app.delete("/expenses/:id", async (req, res) => {
    const id = req.params.id;
    const client = await pool.connect();

    try {
        const deleteQuery = "DELETE FROM expenses WHERE id = $1";
        await client.query(deleteQuery, [id]);

        res.json({
            status: "success",
            message: "Expenses deleted successfully",
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error });
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
