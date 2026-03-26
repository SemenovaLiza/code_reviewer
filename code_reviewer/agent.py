from dotenv import load_dotenv
from transformers import pipeline
from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.prompts import ChatPromptTemplate


load_dotenv()

pipe = pipeline("text-generation", model="openai-community/gpt2")

@tool('investigate_vulnerabilities', description='Semgrep cli tool for code vulnerabiltiies lookup.')
def get_vulnerabilities(code: str):
    ...


agent = create_agent(
    model = 'mistral-small-2603',
    tools = [],
    system_prompt = "You are professional code reviewer. Your task is to detect code vulnerabilities, antipatterns and suggest code changes."   
)
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

    app.get("/admin", (req, res) => {
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
response = agent.invoke(
    {
        'messages': {
            'role': 'user', 'content': user_code
        }
    }
)
print(response['messages'][-1].content)