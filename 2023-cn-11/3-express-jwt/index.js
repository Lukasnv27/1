const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const app = express();
const port = 3000;
const secret_key = "secret_key";
const salt_rounds = 10;

// JSON Web Token er en måde at autentificere brugere på
// Denne token bliver sendt med i alle requests til serveren
// Den kan ikke ændres af brugeren, og den kan ikke læses af brugeren

// bcrypt er en måde at hashe passwords på
// Hashing af passwords er en måde at sikre sig at passwords ikke kan læses
// Det sker ved at anvende en salt til at hashe passwords
// En salt er en tilfældig streng som bliver tilføjet til passwordet inden det bliver hashed
// Når et password bliver hashed med en salt, så er det umuligt at finde frem til det oprindelige password

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// SQLite database
const db = new sqlite3.Database("./db.sqlite");

db.serialize(function () {
  console.log("creating databases if they don't exist");
  db.run(
    "create table if not exists users (id integer primary key, username text not null, password text not null)"
  );
});

// Tilføjer user til db
const addUserToDatabase = (username, password) => {
  db.run(
    "insert into users (username, password) values (?, ?)",
    [username, password],
    function (err) {
      if (err) {
        console.error(err);
      }
    }
  );
};

// Smart måde at konvertere fra Callback til Promise
// Callback er den funktion der bliver kaldt når db.all er færdig med at hente data
// Promise er en måde at håndtere asynkrone kald på
const getUserByUsername = (userName) => {
  return new Promise((resolve, reject) => {
    db.all(
      "select * from users where userName=(?)",
      [userName],
      (err, rows) => {
        if (err) {
          console.error(err);
          return reject(err);
        }
        return resolve(rows);
      }
    );
  });
};

// Middleware for at checke JWT token på protected routes
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization;

  // Check om der er en token
  if (!token) {
    return res.status(401).json({ message: "Token not provided" });
  }

  // Check om token er valid
  jwt.verify(token, secret_key, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

// Opret bruger
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  // Hash password før det gemmes i databasen
  const hashedPassword = await bcrypt.hash(password, salt_rounds);

  // Kald funktion for at tilføje bruger til databasen
  addUserToDatabase(username, hashedPassword);

  // Svar tilbage med en status kode 201 (created) og en besked
  res.status(201).json({ message: "User created successfully" });
});

// Check loginoplysninger
app.post("/authenticate", async (req, res) => {
  const { username, password } = req.body;
  console.log(req.body);

  // Hent brugeren ud fra databasen
  const user = await getUserByUsername(username);
  console.log(user);

  // Check om brugeren findes i databasen og om passwordet er korrekt
  if (!user || !(await bcrypt.compare(password, user[[0]].password))) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Opret en JWT token
  const token = jwt.sign({ username }, secret_key);

  res.json({ token });
});

// Protected route
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "This is a protected route", user: req.user });
});

// Start server
app.listen(port, () => {
  console.log("Server listening on port " + port);
});
