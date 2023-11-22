const express = require("express");
const session = require("express-session");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const app = express();
const port = 3000;

// Middleware
app.use(express.static(__dirname + "/public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session
app.use(
  session({
    secret: "Keep it secret",
    resave: false,
    name: "uniqueSessionID",
    saveUninitialized: false,
    cookie: {
      secure: false,
      maxAge: 3600000,
    },
  })
);

// SQLite database
const db = new sqlite3.Database("./db.sqlite");

db.serialize(function () {
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
const getUserByUsername = (username) => {
  return new Promise((resolve, reject) => {
    db.all(
      "select * from users where username=(?)",
      [username],
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

// Funktion til at hashe password
const hashPassword = (password) => {
  const hash = crypto.createHash('sha256');
  const stream = hash.update(password, 'utf-8');
  stream.end();
  return hash.digest('hex');
};

// Hvis brugeren er logget ind, så sendes de til dashboard, ellers sendes de til login siden
app.get("/", (req, res) => {
  if (req.session.loggedIn) {
    return res.redirect("/dashboard");
  } else {
    return res.sendFile("login.html", { root: path.join(__dirname, "public") });
  }
});

// Et dashboard som kun brugere med 'loggedIn' = true i session kan se
app.get("/dashboard", (req, res) => {
  if (req.session.loggedIn) {
    return res.sendFile("dashboard.html", {
      root: path.join(__dirname, "public"),
    });
  } else {
    return res.redirect("/");
  }
});

// Side til at oprette bruger
app.get("/signup", (req, res) => {
  if (req.session.loggedIn) {
    return res.redirect("/dashboard");
  } else {
    return res.sendFile("signup.html", {
      root: path.join(__dirname, "public"),
    });
  }
});
// Hashing ses nedenfor 
// Opret bruger i databasen
app.post("/signup", async (req, res) => {
  const user = await getUserByUsername(req.body.username);
  if (user.length > 0) {
    return res.send("Username already exists");
  }

  const hashedPassword = hashPassword(req.body.password);
  addUserToDatabase(req.body.username, hashedPassword);
  res.redirect("/");
});

// Checker brugerens loginoplysninger
app.post("/authenticate", async (req, res) => {
  const user = await getUserByUsername(req.body.username);
  if (user.length == 0) {
    return res.sendStatus(401); // Bruger ikke fundet
  }

  const hashedPassword = hashPassword(req.body.password);
  if (hashedPassword === user[0].password) {
    req.session.loggedIn = true;
    req.session.username = req.body.username;
    res.redirect("/dashboard");
  } else {
    return res.sendStatus(401); // Forkert password
  }
});

// Log ud
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {});
  return res.sendFile("logout.html", { root: path.join(__dirname, "public") });
});

// Start server
app.listen(port, () => {
  console.log("Server listening on port " + port);
});
