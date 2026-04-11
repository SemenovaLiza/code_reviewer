# this is a "code" with vulnerabilitie and antipatterns to test agent
user_code = """
    // app.js
    const express = require("express");
    const fs = require("fs");
    const sqlite3 = require("sqlite3").verbose();
    const app = express();

    app.use(express.json());

    const JWT_SECRET = "super_secret_123";

    let currentUser = null;

    const db = new sqlite3.Database("users.db");

    db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT
    )
    `);

    app.post("/register", (req, res) => {
    const { username, password } = req.body;

    const query = `INSERT INTO users (username, password) VALUES ('${username}', '${password}')`;

    db.run(query, (err) => {
        if (err) {
        return res.status(500).send(err.message);
        }
        res.send("User created");
    });
    });

    app.post("/login", (req, res) => {
    const { username, password } = req.body;

    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

    db.get(query, (err, row) => {
        if (err) {
        return res.send(err);
        }

        if (!row) {
        return res.send("Invalid credentials");
        }

        currentUser = row;

        const token = Buffer.from(username + ":" + password).toString("base64");

        res.send({ token });
    });
    });

    function auth(req, res, next) {
    const token = req.headers["authorization"];

    const decoded = Buffer.from(token, "base64").toString();

    if (!decoded) {
        return res.send("Unauthorized");
    }

    next();
    }

    app.get("/file", auth, (req, res) => {
    const fileName = req.query.name;

    const data = fs.readFileSync("./files/" + fileName, "utf-8");

    res.send(data);
    });

    app.geit("/admin", (req, res) => {
    res.send("Welcome admin " + currentUser.username);
    });

    let logs = [];

    app.post("/log", (req, res) => {
    logs.push(req.body);
    res.send("Logged");
    });

    app.listen(3000, () => {
    console.log("Server running on port 3000");
    });
"""
# this code is for testing api
code = "// app.js\n    const express = require(\"express\");\n    const fs = require(\"fs\");\n    const sqlite3 = require(\"sqlite3\").verbose();\n    const app = express();\n\n    app.use(express.json());\n\n    const JWT_SECRET = \"super_secret_123\";\n\n    let currentUser = null;\n\n    const db = new sqlite3.Database(\"users.db\");\n\n    db.run(`\n    CREATE TABLE IF NOT EXISTS users (\n        id INTEGER PRIMARY KEY,\n        username TEXT,\n        password TEXT\n    )\n    `);\n\n    app.post(\"/register\", (req, res) => {\n    const { username, password } = req.body;\n\n    const query = `INSERT INTO users (username, password) VALUES ('${username}', '${password}')`;\n\n    db.run(query, (err) => {\n        if (err) {\n        return res.status(500).send(err.message);\n        }\n        res.send(\"User created\");\n    });\n    });\n\n    app.post(\"/login\", (req, res) => {\n    const { username, password } = req.body;\n\n    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;\n\n    db.get(query, (err, row) => {\n        if (err) {\n        return res.send(err);\n        }\n\n        if (!row) {\n        return res.send(\"Invalid credentials\");\n        }\n\n        currentUser = row;\n\n        const token = Buffer.from(username + \":\" + password).toString(\"base64\");\n\n        res.send({ token });\n    });\n    });\n\n    function auth(req, res, next) {\n    const token = req.headers[\"authorization\"];\n\n    const decoded = Buffer.from(token, \"base64\").toString();\n\n    if (!decoded) {\n        return res.send(\"Unauthorized\");\n    }\n\n    next();\n    }\n\n    app.get(\"/file\", auth, (req, res) => {\n    const fileName = req.query.name;\n\n    const data = fs.readFileSync(\"./files/\" + fileName, \"utf-8\");\n\n    res.send(data);\n    });\n\n    app.geit(\"/admin\", (req, res) => {\n    res.send(\"Welcome admin \" + currentUser.username);\n    });\n\n    let logs = [];\n\n    app.post(\"/log\", (req, res) => {\n    logs.push(req.body);\n    res.send(\"Logged\");\n    });\n\n    app.listen(3000, () => {\n    console.log(\"Server running on port 3000\");\n    });"