const express = require('express');
const cors = require('cors');
const path = require('path');
const {v4: uuidv4, stringify} = require('uuid');
const sql = require('mssql');
const bcrypt = require('bcrypt');
const schedule = require('node-schedule');
const HTTP_PORT = 8080;
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
require('dotenv').config();

console.log('Listening on port ' +  HTTP_PORT);
var app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

// Serve static files from the root directory
app.use(express.static(__dirname));

const config = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    port: 1433,
    database: process.env.DB_DATABASE,
    authentication: {
        type: 'default',
    },
    options: {
        encrypt: true,
    },
};

// Create a connection pool
let poolPromise = sql.connect(config)
    .then(pool => {
       console.log('Connected to database');
        return pool;
    })
    .catch(err => {
        console.error('Database connection failed:', err);
        process.exit(1);
    });

// Create a new user and return userID
app.post('/users', async (req, res) => {
    const strFirstName = req.body.firstName?.trim();
    const strLastName = req.body.lastName?.trim();
    const strUsername = req.body.username?.trim();
    const strEmail = req.body.email?.trim().toLowerCase();
    const strPassword = req.body.password;
    const strUserID = uuidv4();

    if (
        !strFirstName ||
        !strLastName ||
        !strUsername ||
        !strEmail ||
        !strPassword
    ) {
        return res.status(400).json({
            message: 'Missing required fields.'
        });
    }

    try {
        const pool = await poolPromise;

        // Check for an existing username or email.
        const existingResult = await pool.request()
            .input('Username', sql.VarChar, strUsername)
            .input('Email', sql.VarChar, strEmail)
            .query(`
                SELECT Username, Email
                FROM dbo.tblUsers
                WHERE Username = @Username
                   OR Email = @Email
            `);

        const errors = {};

        for (const user of existingResult.recordset) {
            if (
                user.Username &&
                user.Username.toLowerCase() === strUsername.toLowerCase()
            ) {
                errors.username = 'That username is already taken.';
            }

            if (
                user.Email &&
                user.Email.toLowerCase() === strEmail.toLowerCase()
            ) {
                errors.email = 'An account already exists with that email.';
            }
        }

        if (Object.keys(errors).length > 0) {
            return res.status(409).json({
                message: 'Username or email is already in use.',
                errors
            });
        }

        const hashedPassword = await bcrypt.hash(strPassword, 10);

        await pool.request()
            .input('UserID', sql.UniqueIdentifier, strUserID)
            .input('Email', sql.VarChar, strEmail)
            .input('Username', sql.VarChar, strUsername)
            .input('Password', sql.VarChar, hashedPassword)
            .input('FirstName', sql.VarChar, strFirstName)
            .input('LastName', sql.VarChar, strLastName)
            .query(`
                INSERT INTO dbo.tblUsers
                    (UserID, Email, Username, Password, FirstName, LastName)
                VALUES
                    (@UserID, @Email, @Username, @Password, @FirstName, @LastName)
            `);

        return res.status(201).json({
            message: 'Account created successfully.',
            userID: strUserID,
            email: strEmail
        });
    } catch (err) {
        console.error('Error creating user:', err);

        // Handles a rare race condition where another account is created
        // after the duplicate check but before this insert.
        if (err.number === 2601 || err.number === 2627) {
            return res.status(409).json({
                message: 'Username or email is already in use.',
                errors: {
                    account: 'That username or email was just registered. Please try another.'
                }
            });
        }

        return res.status(500).json({
            message: 'Could not create user.'
        });
    }
});

app.get('/user', async (req, res) => {
    const strUserID = req.query.userID;

    if (!strUserID) {
        return res.status(400).json({
            error: "UserID is required"
        });
    }

    try{
        const pool = await poolPromise;
        const result = await pool.request()
            .input('UserID', sql.UniqueIdentifier, strUserID)
            .query('SELECT UserID, Username, Email FROM tblUsers WHERE UserID = @UserID');

        if (result.recordset.length === 0) {
            return res.status(404).json({
                error: "User not found"
            });
        }

        const user = result.recordset[0];
        return res.status(200).json({
            userID: user.UserID,
            username: user.Username,
            email: user.Email
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({
            error: "Server error"
        });
    }
});

// Get userID while verifying user exists
app.post('/login', async (req, res) => {
    const strIdentifier = req.body.identifier;
    const strPassword = req.body.password;
    const blnRememberMe =
        req.body.rememberMe === 'true' ||
        req.body.rememberMe === true;

    if (!strIdentifier || !strPassword) {
        return res.status(400).json({
            error: "Email/username and password are required"
        });
    }

    try {
        const pool = await poolPromise;

        // Find user by email OR username
        const result = await pool.request()
            .input('Identifier', sql.VarChar, strIdentifier)
            .query(`
                SELECT UserID, Email, Password
                FROM tblUsers
                WHERE Email = @Identifier
                   OR Username = @Identifier
            `);

        if (result.recordset.length === 0) {
            return res.status(401).json({
                error: "Invalid email, username, or password"
            });
        }

        const user = result.recordset[0];

        // Authenticate password ONCE
        const match = await bcrypt.compare(
            strPassword,
            user.Password
        );

        if (!match) {
            return res.status(401).json({
                error: "Invalid email, username, or password"
            });
        }

        // Create session
        const strSessionID = uuidv4();

        const expiresAt = new Date();

        if (blnRememberMe) {
            // Remember Me: 30 days
            expiresAt.setUTCDate(expiresAt.getUTCDate() + 30);
        } else {
            // Normal session: 24 hours
            expiresAt.setUTCHours(expiresAt.getUTCHours() + 24);
        }

        await pool.request()
            .input(
                'SessionID',
                sql.UniqueIdentifier,
                strSessionID
            )
            .input(
                'UserID',
                sql.UniqueIdentifier,
                user.UserID
            )
            .input(
                'ExpiresAt',
                sql.DateTime2,
                expiresAt
            )
            .query(`
                INSERT INTO tblSessions
                    (SessionID, UserID, ExpiresAt)
                VALUES
                    (@SessionID, @UserID, @ExpiresAt)
            `);

        return res.status(200).json({
            message: "success",
            userID: user.UserID,
            email: user.Email,
            sessionid: strSessionID
        });

    } catch (err) {
        console.error(err);

        return res.status(500).json({
            error: "Server error"
        });
    }
});

// Forgot password, send email with reset link
app.post('/forgotPassword', async (req, res, next) => {
    const email = req.body.email;

    if (!email) {
        res.status(400).json({ error: 'Email is required' });
        return;
    }

    try {
        const pool = await poolPromise;

        // Step 1. Find user by email
        const userResult = await pool.request()
            .input('email', sql.VarChar, email)
            .query('SELECT UserID FROM tblUsers WHERE Email = @Email');
        
        if (userResult.recordset.length === 0) {
            return res.json({ message: "If that email is registered, a reset link has been sent."})
        }

        const userID = userResult.recordset[0].UserID;

        // Step 2. Generate token + expiration (eg. 1 hour from now)
        const token = uuidv4();
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour from now

        // Step 3. Store token in database
        await pool.request()
            .input('Token', sql.UniqueIdentifier, token)
            .input('UserID', sql.UniqueIdentifier, userID)
            .input('ExpiresAt', sql.DateTime, expiresAt)
            .query(`INSERT INTO tblPasswordResetTokens (Token, UserID, ExpiresAt)
                     VALUES (@Token, @UserID, @ExpiresAt)`);

        // Step 4. Send email with reset link
        const resetLink = `https://collegefootballbattleship.com/reset-password.html?token=${token}`;

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        await transporter.sendMail({
            to: email,
            subject: 'Password Reset - College Football Battleship',
            html: `
                <p>Hello,</p>
                <p>You requested a password reset. Click below to reset your password:</p>
                <p><a href="${resetLink}">${resetLink}</a></p>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, you can safely ignore it.</p>
            `
        })

        res.json({ message: "If that email is registered, a reset link has been sent." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/resetPassword', async (req, res, next) => {
    const {token, newPassword} = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Token and new password are required' });
    }

    try {
        const pool = await poolPromise;

        // Step 1. Validate token
        const tokenResult = await pool.request()
            .input('Token', sql.UniqueIdentifier, token)
            .query('SELECT UserID, ExpiresAt FROM tblPasswordResetTokens WHERE Token = @Token AND ExpiresAt > GETDATE()');
        
        if (tokenResult.recordset.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }

        const userID = tokenResult.recordset[0].UserID;

        // Step 2. Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Step 3. Update user's password
        await pool.request()
            .input('passwordHash', sql.VarChar, hashedPassword)
            .input('UserID', sql.VarChar, userID)
            .query('UPDATE tblUsers SET Password = @passwordHash WHERE UserID = @UserID');
        
        // Step 4. Invalidate token
        await pool.request()
            .input("Token", sql.UniqueIdentifier, token)
            .query('DELETE FROM tblPasswordResetTokens WHERE Token = @Token');
        
        res.json({ message: 'Password has been reset successfully' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Server error' });
    }
});

// Change password of user
app.put('/users', async (req, res, next) => {
    let email = req.body.email;
    let newPassword = req.body.newPassword;
    let strUserID = req.query.userID;

    if (!email || !newPassword || !strUserID) {
        res.status(400).json({ error: 'Missing required fields' });
        return;
    } else {
        try {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            const pool = await poolPromise;

            // Execute the query
            const request = pool.request();
            request.input('UserID', sql.UniqueIdentifier, strUserID);
            request.input('Email', sql.VarChar, email);
            request.input('Password', sql.VarChar, hashedPassword);

            const result = await request.query(
                `UPDATE tblUsers
                    SET Password = @Password
                    WHERE UserID = @UserID AND Email = @Email`
            );

            res.status(200).json({
                message: "success",
                email: email
            });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: err.message });
        }
    }
});

// Check if user exists
app.get('/userExists', async (req, res, next) => {
    let strEmail = req.query.email;

    if (strEmail) {
        try {
            const pool = await poolPromise;

            const result = await pool.request()
                .input('Email', sql.VarChar, strEmail)
                .query('SELECT * FROM tblUsers WHERE Email = @Email');

            if (result.recordset.length > 0) {
                res.status(200).json({
                    message: "success",
                    userExists: true,
                    userID: result.recordset[0].UserID
                });
            } else {
                res.status(200).json({
                    message: "success",
                    userExists: false
                });
            }
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: "Email is required" });
    }
});

// Gets userID from tblSessions using SessionID
app.get('/userID', async (req, res, next) => {
    let strSessionID = req.query.SessionID;

    const guidRegex =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    if (!strSessionID || !guidRegex.test(strSessionID)) {
        console.log("Invalid SessionID received:", strSessionID);

        return res.status(400).json({
            message: "Invalid SessionID"
        });
    }

    try {
        const pool = await poolPromise;

        const result = await pool.request()
            .input('SessionID', sql.UniqueIdentifier, strSessionID)
            .query(`
                SELECT UserID
                FROM dbo.tblSessions
                WHERE SessionID = @SessionID
                AND ExpiresAt > SYSUTCDATETIME()
            `);

        if (result.recordset.length > 0) {
            res.status(200).json({
                message: "success",
                userID: result.recordset[0].UserID
            });
        } else {
            res.status(200).json({
                message: "Session not found or expired"
            });
        }
    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: "Server error"
        });
    }
});

// Create a session and return SessionID
app.post('/sessions', async (req, res, next) => {
    let strEmail = req.body.email;
    let strPassword = req.body.password;
    let blnRememberMe = req.body.rememberMe === 'true' || req.body.rememberMe === true;

    let strSessionID = uuidv4();

    if (strEmail && strPassword) {
        try {
            const pool = await poolPromise;

            // Step 1: Get the hashed password from the database
            const result = await pool.request()
                .input('Email', sql.VarChar, strEmail)
                .query(`
                    SELECT Password
                    FROM tblUsers
                    WHERE Email = @Email
                `);

            if (result.recordset.length > 0) {
                let hashedPass = result.recordset[0].Password;

                // Step 2: Compare the provided password with the hashed password
                const match = await bcrypt.compare(strPassword, hashedPass);

                if (match) {
                    // Step 3: Retrieve the UserID from the database
                    const userResult = await pool.request()
                        .input('Email', sql.VarChar, strEmail)
                        .input('Password', sql.VarChar, hashedPass)
                        .query(`
                            SELECT UserID
                            FROM tblUsers
                            WHERE Email = @Email
                            AND Password = @Password
                        `);

                    if (userResult.recordset.length > 0) {
                        let strUserID = userResult.recordset[0].UserID;

                        // Determine session expiration
                        let expiresAt = new Date();

                        if (blnRememberMe) {
                            // Remember Me = 30 days
                            expiresAt.setUTCDate(expiresAt.getUTCDate() + 30);
                        } else {
                            // Normal session = 24 hours
                            expiresAt.setUTCHours(expiresAt.getUTCHours() + 24);
                        }

                        // Step 4: Insert new session
                        await pool.request()
                            .input('SessionID', sql.UniqueIdentifier, strSessionID)
                            .input('UserID', sql.UniqueIdentifier, strUserID)
                            .input('ExpiresAt', sql.DateTime2, expiresAt)
                            .query(`
                                INSERT INTO tblSessions (
                                    SessionID,
                                    UserID,
                                    ExpiresAt
                                )
                                VALUES (
                                    @SessionID,
                                    @UserID,
                                    @ExpiresAt
                                )
                            `);

                        res.status(201).json({
                            message: "success",
                            sessionid: strSessionID
                        });
                    } else {
                        res.status(400).json({
                            error: "User not found"
                        });
                    }
                } else {
                    res.status(400).json({
                        error: "Invalid password"
                    });
                }
            } else {
                res.status(400).json({
                    error: "Email not found"
                });
            }
        } catch (err) {
            console.error(err);

            res.status(500).json({
                error: err.message
            });
        }
    } else {
        res.status(400).json({
            error: "Not all parameters provided"
        });
    }
});

// Delete SessionID from Database
app.delete('/sessions', async (req, res, next) => {
    let strSessionID = req.query.SessionID;

    if (!strSessionID) {
        res.status(400).json({ error: "SessionID is required" });
        return;
    }

    try {
        const pool = await poolPromise;

        // Execute the delete command
        const result = await pool.request()
            .input('SessionID', sql.UniqueIdentifier, strSessionID)
            .query('DELETE FROM tblSessions WHERE SessionID = @SessionID');

        if (result.rowsAffected[0] > 0) {
            res.status(201).json({
                message: "SessionID successfully deleted"
            });
        } else {
            res.status(400).json({ error: "SessionID not found" });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Create a group and return groupID and groupName
app.post('/groups', async (req, res, next) => {
    let strGroupName = req.body.groupName;
    let strOwnerID = req.body.ownerID;
    let strOwnerName;
    let strPassword = req.body.password;
    let strGroupID = uuidv4();

    try {
        const pool = await poolPromise;

        // Get the owner username from tblUsers
        const ownerResult = await pool.request()
            .input('UserID', sql.UniqueIdentifier, strOwnerID)
            .query('SELECT Username FROM tblUsers WHERE UserID = @UserID');

        if (ownerResult.recordset.length > 0) {
            strOwnerName = ownerResult.recordset[0].Username;

            // Hash the password if it is not empty
            if (strPassword !== '') {
                strPassword = await bcrypt.hash(strPassword, 10);
            }

            // Insert into tblGroups
            await pool.request()
                .input('GroupID', sql.UniqueIdentifier, strGroupID)
                .input('GroupName', sql.VarChar, strGroupName)
                .input('OwnerName', sql.VarChar, strOwnerName)
                .input('OwnerID', sql.UniqueIdentifier, strOwnerID)
                .input('Password', sql.VarChar, strPassword)
                .query('INSERT INTO tblGroups (GroupID, GroupName, OwnerName, OwnerID, Password) VALUES (@GroupID, @GroupName, @OwnerName, @OwnerID, @Password)');

            res.status(201).json({
                message: "success",
                groupID: strGroupID,
                groupName: strGroupName
            });
        } else {
            res.status(400).json({ error: "Owner not found" });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Get all groups
app.get('/groups', async (req, res, next) => {
    try {
        const pool = await poolPromise;

        // Execute the query to select all groups
        const result = await pool.request()
            .query('SELECT * FROM tblGroups');

        if (result.recordset.length > 0) {
            res.status(200).json(result.recordset);
        } else {
            res.status(200).json([]); // Return an empty array if no groups are found
        }
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: err.message });
    }
});

// Get group by groupID
app.get('/groupByID', async (req, res, next) => {
    let strGroupID = req.query.groupID;
    
    if (!strGroupID) {
        res.status(400).json({ error: "Not all parameters provided" });
        return;
    }

    try {
        const pool = await poolPromise;

        // Execute the query to select the group by ID
        const result = await pool.request()
            .input('GroupID', sql.UniqueIdentifier, strGroupID)
            .query('SELECT * FROM tblGroups WHERE GroupID = @GroupID');

        if (result.recordset.length > 0) {
            res.status(200).json(result.recordset[0]); // Return the first matching row
        } else {
            res.status(400).json({ error: "Group not found" });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

getFirstGame = async () => {
    try {
        const gamesData = await getAllGames();
        return gamesData[0];
    } catch (error) {
        console.error('Error fetching first game:', error);
        throw new Error('Failed to fetch the first game');
    }
};

const hasJoinDeadlinePassed = async () => {
    const firstGame = await getFirstGame();

    const joinCutoff = new Date(firstGame.startDate);

    // Allow joining for 7 days after first game starts
    joinCutoff.setDate(joinCutoff.getDate() + 7);

    return new Date() >= joinCutoff;
};

// Add a user to a group
app.post('/groupmembers', async (req, res, next) => {
    let strGroupID = req.body.groupID;
    let strGroupName = req.body.groupName;
    let strUserID = req.body.userID;
    let strGroupPassword = req.body.groupPassword;

    if (!strGroupID || !strGroupName || !strUserID) {
        res.status(400).json({ error: 'Not all parameters provided' });
        return;
    }

    try {
        const pool = await poolPromise;

        // ---------------------------------------
        // CHECK IF GROUP JOIN DEADLINE HAS PASSED
        // ---------------------------------------
        // Prevent initialization after join deadline
        if (await hasJoinDeadlinePassed()) {
            return res.status(403).json({
                error: "The deadline to join a group has passed"
            });
        }

        // Get hashed group password from the database
        const groupResult = await pool.request()
            .input('GroupID', sql.UniqueIdentifier, strGroupID)
            .query('SELECT Password FROM tblGroups WHERE GroupID = @GroupID');

        if (groupResult.recordset.length > 0) {
            let hashedPass = groupResult.recordset[0].Password;

            // If hashed password is empty, add user to group
            if (!hashedPass) {
                const userResult = await pool.request()
                    .input('UserID', sql.UniqueIdentifier, strUserID)
                    .query('SELECT Username FROM tblUsers WHERE UserID = @UserID');

                if (userResult.recordset.length > 0) {
                    let strUsername = userResult.recordset[0].Username;

                    await pool.request()
                        .input('GroupID', sql.UniqueIdentifier, strGroupID)
                        .input('GroupName', sql.VarChar, strGroupName)
                        .input('UserID', sql.UniqueIdentifier, strUserID)
                        .input('Username', sql.VarChar, strUsername)
                        .query('INSERT INTO tblGroupMembers (GroupID, GroupName, UserID, Username) VALUES (@GroupID, @GroupName, @UserID, @Username)');

                    res.status(201).json({
                        message: "Member successfully added to the group"
                    });
                } else {
                    res.status(400).json({ error: "User not found" });
                }
            } else {
                // If hashed password is not empty, compare hashed group password with input password
                const passwordMatch = await bcrypt.compare(strGroupPassword, hashedPass);

                if (passwordMatch) {
                    const userResult = await pool.request()
                        .input('UserID', sql.UniqueIdentifier, strUserID)
                        .query('SELECT Username FROM tblUsers WHERE UserID = @UserID');

                    if (userResult.recordset.length > 0) {
                        let strUsername = userResult.recordset[0].Username;

                        await pool.request()
                            .input('GroupID', sql.UniqueIdentifier, strGroupID)
                            .input('GroupName', sql.VarChar, strGroupName)
                            .input('UserID', sql.UniqueIdentifier, strUserID)
                            .input('Username', sql.VarChar, strUsername)
                            .query('INSERT INTO tblGroupMembers (GroupID, GroupName, UserID, Username) VALUES (@GroupID, @GroupName, @UserID, @Username)');

                        res.status(201).json({
                            message: "Member successfully added to the group"
                        });
                    } else {
                        res.status(400).json({ error: "User not found" });
                    }
                } else {
                    res.status(200).json({ error: "Invalid Group Password" });
                }
            }
        } else {
            res.status(400).json({ error: "Group not found" });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Get all group members by groupID
app.get('/groupmembers', async (req, res, next) => {
    let strGroupID = req.query.groupID;

    if (!strGroupID) {
        res.status(400).json({ error: "GroupID is required" });
        return;
    }

    try {
        const pool = await poolPromise;

        // Execute the query to select all group members by GroupID
        const result = await pool.request()
            .input('GroupID', sql.UniqueIdentifier, strGroupID)
            .query('SELECT * FROM tblGroupMembers WHERE GroupID = @GroupID');

        res.status(200).json({
            message: "success",
            members: result.recordset
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Get groups by UserID
app.get('/groupsByUserID', async (req, res, next) => {
    let strUserID = req.query.userID;

    if (!strUserID) {
        res.status(400).json({ error: "UserID is required" });
        return;
    }

    try {
        const pool = await poolPromise;

        // Execute the query to select all groups by UserID
        const result = await pool.request()
            .input('UserID', sql.UniqueIdentifier, strUserID)
            .query('SELECT * FROM tblGroupMembers WHERE UserID = @UserID');

        res.status(200).json({
            message: "success",
            groups: result.recordset
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Get group owner by groupID
app.get('/groupOwner', async (req, res, next) => {
    let strGroupID = req.query.groupID;

    if (!strGroupID) {
        res.status(400).json({ error: "GroupID is required" });
        return;
    }

    try {
        const pool = await poolPromise;

        // Execute the query to select the owner name by GroupID
        const result = await pool.request()
            .input('GroupID', sql.UniqueIdentifier, strGroupID)
            .query('SELECT OwnerName FROM tblGroups WHERE GroupID = @GroupID');

        if (result.recordset.length > 0) {
            res.status(200).json({
                message: "here",
                owner: result.recordset[0].OwnerName
            });
        } else {
            res.status(404).json({ error: "Group not found" });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Validate game for selection
async function validateGameForSelection(
    gameID,
    pickedTeam = null
) {
    const games = await getCachedGames(
        year,
        currentFootballWeekNumber
    );

    const game = games.find(
        game =>
            Number(game.id) === Number(gameID)
    );

    if (!game) {
        return {
            valid: false,
            status: 409,
            error:
                'This game is not available for selections in the current week.'
        };
    }

    const gameStartTime =
        new Date(game.startDate).getTime();

    if (Number.isNaN(gameStartTime)) {
        return {
            valid: false,
            status: 500,
            error:
                'Unable to determine game start time.'
        };
    }

    if (Date.now() >= gameStartTime) {
        return {
            valid: false,
            status: 409,
            error:
                'This game has already started. Picks can no longer be changed.'
        };
    }

    /*
        POST/PUT only:
        Verify selected team belongs to this game.
    */
    if (pickedTeam !== null) {

        if (
            pickedTeam !== game.homeTeam &&
            pickedTeam !== game.awayTeam
        ) {
            return {
                valid: false,
                status: 400,
                error:
                    'The selected team is not part of this game.'
            };
        }

        /*
            Determine selected team's classification.
        */
        const selectedClassification =
            pickedTeam === game.homeTeam
                ? game.homeClassification
                : game.awayClassification;

        /*
            Only FBS schools are eligible.
        */
        if (
            selectedClassification?.toLowerCase() !== 'fbs'
        ) {
            return {
                valid: false,
                status: 400,
                error:
                    'Only FBS teams are eligible to be selected.'
            };
        }
    }

    return {
        valid: true,
        game
    };
}

// Send made picks to database
app.post('/selection', async (req, res) => {
    const strUserID = req.body.userID;
    const strPickedTeam = req.body.pickedTeam;
    const strGroupID = req.body.groupID;
    const intGameID = Number(req.body.gameID);
    const intWeek = Number(req.body.week);

    if (
        !strUserID ||
        !strPickedTeam ||
        !strGroupID ||
        !intGameID ||
        !intWeek
    ) {
        return res.status(400).json({
            error: 'Not all parameters provided.'
        });
    }

    /*
        Do your game-start validation BEFORE opening
        the SQL transaction so the transaction stays short.
    */
    const validation =
        await validateGameForSelection(
            intGameID,
            strPickedTeam
        );

    if (!validation.valid) {
        return res
            .status(validation.status)
            .json({
                error: validation.error
            });
    }

    const pool = await poolPromise;

    const transaction =
        new sql.Transaction(pool);

    try {

        /*
            SERIALIZABLE is important here.

            It prevents another transaction from
            inserting into the range we're checking
            until this transaction finishes.
        */
        await transaction.begin(
            sql.ISOLATION_LEVEL.SERIALIZABLE
        );


        /*
            1. Check whether this user already has
               a selection for this exact game.
        */
        const existingGameRequest =
            new sql.Request(transaction);

        const existingGameResult =
            await existingGameRequest

                .input(
                    'UserID',
                    sql.UniqueIdentifier,
                    strUserID
                )

                .input(
                    'GroupID',
                    sql.UniqueIdentifier,
                    strGroupID
                )

                .input(
                    'GameID',
                    sql.Int,
                    intGameID
                )

                .query(`
                    SELECT
                        PickedTeam

                    FROM tblSelections
                    WITH (UPDLOCK, HOLDLOCK)

                    WHERE UserID = @UserID
                    AND GroupID = @GroupID
                    AND GameID = @GameID
                `);


        /*
            A selection already exists for this game.
        */
        if (
            existingGameResult.recordset.length > 0
        ) {

            await transaction.rollback();

            return res.status(409).json({
                error:
                    'You already have a selection for this game.'
            });
        }


        /*
            2. Get number of picks allowed.
        */
        const picksLeftRequest =
            new sql.Request(transaction);

        const picksLeftResult =
            await picksLeftRequest

                .input(
                    'UserID',
                    sql.UniqueIdentifier,
                    strUserID
                )

                .input(
                    'GroupID',
                    sql.UniqueIdentifier,
                    strGroupID
                )

                .input(
                    'Week',
                    sql.Int,
                    intWeek
                )

                .query(`
                    SELECT TOP 1
                        PicksLeft

                    FROM tblPicksLeft

                    WHERE UserID = @UserID
                    AND GroupID = @GroupID
                    AND Week <= @Week

                    ORDER BY Week DESC
                `);


        if (
            picksLeftResult.recordset.length === 0
        ) {

            await transaction.rollback();

            return res.status(404).json({
                error:
                    'Picks remaining could not be found.'
            });
        }


        const intPicksAllowed =
            Number(
                picksLeftResult
                    .recordset[0]
                    .PicksLeft
            );


        /*
            3. Count selections already made this week.
        */
        const countRequest =
            new sql.Request(transaction);

        const countResult =
            await countRequest

                .input(
                    'UserID',
                    sql.UniqueIdentifier,
                    strUserID
                )

                .input(
                    'GroupID',
                    sql.UniqueIdentifier,
                    strGroupID
                )

                .input(
                    'Week',
                    sql.Int,
                    intWeek
                )

                .query(`
                    SELECT
                        COUNT(*) AS SelectionCount

                    FROM tblSelections
                    WITH (UPDLOCK, HOLDLOCK)

                    WHERE UserID = @UserID
                    AND GroupID = @GroupID
                    AND Week = @Week
                `);


        const intCurrentSelections =
            Number(
                countResult
                    .recordset[0]
                    .SelectionCount
            );


        /*
            User already made all allowed picks.
        */
        if (
            intCurrentSelections >=
            intPicksAllowed
        ) {

            await transaction.rollback();

            return res.status(409).json({
                error:
                    `You have already made all ${intPicksAllowed} picks. Remove a pick before selecting another.`
            });
        }


        /*
            4. Check whether this exact team has
               already been selected this week.
        */
        const duplicateTeamRequest =
            new sql.Request(transaction);

        const duplicateTeamResult =
            await duplicateTeamRequest

                .input(
                    'UserID',
                    sql.UniqueIdentifier,
                    strUserID
                )

                .input(
                    'GroupID',
                    sql.UniqueIdentifier,
                    strGroupID
                )

                .input(
                    'Week',
                    sql.Int,
                    intWeek
                )

                .input(
                    'PickedTeam',
                    sql.VarChar(100),
                    strPickedTeam
                )

                .query(`
                    SELECT
                        PickedTeam

                    FROM tblSelections
                    WITH (UPDLOCK, HOLDLOCK)

                    WHERE UserID = @UserID
                    AND GroupID = @GroupID
                    AND Week = @Week
                    AND PickedTeam = @PickedTeam
                `);


        if (
            duplicateTeamResult.recordset.length > 0
        ) {

            await transaction.rollback();

            return res.status(409).json({
                error:
                    'You have already selected this team.'
            });
        }


        /*
            5. Insert selection.
        */
        const insertRequest =
            new sql.Request(transaction);

        await insertRequest

            .input(
                'UserID',
                sql.UniqueIdentifier,
                strUserID
            )

            .input(
                'PickedTeam',
                sql.VarChar(100),
                strPickedTeam
            )

            .input(
                'GroupID',
                sql.UniqueIdentifier,
                strGroupID
            )

            .input(
                'GameID',
                sql.Int,
                intGameID
            )

            .input(
                'Week',
                sql.Int,
                intWeek
            )

            .query(`
                INSERT INTO tblSelections (
                    UserID,
                    PickedTeam,
                    GroupID,
                    GameID,
                    Week,
                    selection_correct
                )

                VALUES (
                    @UserID,
                    @PickedTeam,
                    @GroupID,
                    @GameID,
                    @Week,
                    NULL
                )
            `);


        /*
            Everything succeeded.
        */
        await transaction.commit();

        return res.status(200).json({
            message:
                'Selection added successfully.',
            pickedTeam:
                strPickedTeam,
            gameID:
                intGameID
        });

    } catch (err) {

        /*
            Roll back if the transaction
            is still active.
        */
        try {
            await transaction.rollback();
        } catch (rollbackErr) {
            // Transaction may already be rolled back.
        }

        console.error(err);

        return res.status(500).json({
            error:
                'Unable to create selection.'
        });
    }
});

// Get selections by groupID and userID
app.get('/selection', async (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;

    if (strGroupID && strUserID) {
        try {
            const pool = await poolPromise;

            // Execute the query to select selections by GroupID and UserID
            const result = await pool.request()
                .input('GroupID', sql.UniqueIdentifier, strGroupID)
                .input('UserID', sql.UniqueIdentifier, strUserID)
                .query('SELECT * FROM tblSelections WHERE GroupID = @GroupID AND UserID = @UserID');

            res.status(200).json({
                message: "success",
                selections: result.recordset
            });
        } catch (err) {
            console.error(err);
            res.status(400).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: "Not all parameters provided" });
    }
});

app.put('/selection', async (req, res) => {

    const strUserID =
        req.body.userID;

    const strGroupID =
        req.body.groupID;

    const intGameID =
        Number(req.body.gameID);

    const strPickedTeam =
        req.body.pickedTeam;

    if (
        !strUserID ||
        !strGroupID ||
        !intGameID ||
        !strPickedTeam
    ) {
        return res.status(400).json({
            error: 'Not all parameters provided.'
        });
    }

    try {

        /*
            Check kickoff and make sure
            pickedTeam belongs to the game.
        */
        const validation =
            await validateGameForSelection(
                intGameID,
                strPickedTeam
            );

        if (!validation.valid) {
            return res
                .status(validation.status)
                .json({
                    error: validation.error
                });
        }

        const pool =
            await poolPromise;

        const result =
            await pool.request()

                .input(
                    'UserID',
                    sql.UniqueIdentifier,
                    strUserID
                )

                .input(
                    'GroupID',
                    sql.UniqueIdentifier,
                    strGroupID
                )

                .input(
                    'GameID',
                    sql.Int,
                    intGameID
                )

                .input(
                    'PickedTeam',
                    sql.VarChar(100),
                    strPickedTeam
                )

                .query(`
                    UPDATE tblSelections

                    SET PickedTeam = @PickedTeam

                    WHERE UserID = @UserID
                    AND GroupID = @GroupID
                    AND GameID = @GameID
                `);

        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({
                error: 'Selection not found.'
            });
        }

        return res.status(200).json({
            message:
                'Selection changed successfully.'
        });

    } catch (err) {

        console.error(err);

        return res.status(500).json({
            error:
                'Unable to change selection.'
        });
    }
});

// Delete selection by groupID, userID and gameID
app.delete('/selection', async (req, res) => {


    const strGroupID =
        req.body.groupID;

    const strUserID =
        req.body.userID;

    const intGameID =
        Number(req.body.gameID);

    if (
        !strGroupID ||
        !strUserID ||
        !intGameID
    ) {
        return res.status(400).json({
            error: 'Not all parameters provided.'
        });
    }

    try {

        /*
            Make sure game has not started.
        */
        const validation =
            await validateGameForSelection(
                intGameID
            );
        
        if (!validation.valid) {
            return res
                .status(validation.status)
                .json({
                    error: validation.error
                });
        }

        const pool =
            await poolPromise;

        const result =
            await pool.request()

                .input(
                    'GroupID',
                    sql.UniqueIdentifier,
                    strGroupID
                )

                .input(
                    'UserID',
                    sql.UniqueIdentifier,
                    strUserID
                )

                .input(
                    'GameID',
                    sql.Int,
                    intGameID
                )

                .query(`
                    DELETE FROM tblSelections

                    WHERE GroupID = @GroupID
                    AND UserID = @UserID
                    AND GameID = @GameID
                `);

        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({
                error: 'Selection not found.'
            });
        }

        return res.status(200).json({
            message:
                'Selection removed successfully.'
        });

    } catch (err) {

        console.error(err);

        return res.status(500).json({
            error:
                'Unable to remove selection.'
        });
    }
});

// Get selections by groupID, userID, and current week
app.get('/selectionsByCurrentWeek', async (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;

    if (strGroupID && strUserID) {
        try {
            const pool = await poolPromise;

            // Execute the query to select selections by GroupID, UserID, and current week number
            const result = await pool.request()
                .input('GroupID', sql.UniqueIdentifier, strGroupID)
                .input('UserID', sql.UniqueIdentifier, strUserID)
                .input('Week', sql.Int, currentFootballWeekNumber)
                .query('SELECT * FROM tblSelections WHERE GroupID = @GroupID AND UserID = @UserID AND Week = @Week');

            res.status(200).json({
                message: "success",
                selections: result.recordset
            });
        } catch (err) {
            console.error(err);
            res.status(400).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: "Not all parameters provided" });
    }
});

// Get weeks game data
app.get('/weekData', async (req, res, next) => {
    try {
        const weekData = await getWeekData();
        res.status(200).json(weekData);
    } catch (error) {
        console.error('Error fetching week data:', error);
        res.status(500).json({ error: 'Failed to fetch week data' });
    }
});

// Get week number
app.get('/weekNumber', (req, res, next) => {
    res.status(200).json({
        message:"success",
        weekNumber:currentFootballWeekNumber
    })
});

// get game startDate by gameID
app.get('/gameStartDate', (req, res, next) => {
    let strGameID = req.query.gameID;

    getStartDate(strGameID, function(startDate){
        res.status(200).json(startDate);
    })
});

// get game data by game id
app.get('/gameData', async (req, res, next) => {
    try {
        const strGameID = req.query.gameID;
        const gameData = await getGameData(strGameID);
        res.status(200).json(gameData);
    } catch (error) {
        console.error('Error fetching game data:', error);
        res.status(500).json({ error: 'Failed to fetch game data' });
    }
});

// get all teams
app.get('/teams', async (req, res, next) => {
    try {
        const year = req.query.year;
        const teams = await getTeams(year);
        res.status(200).json(teams);
    } catch (error) {
        console.error('Error fetching teams:', error);
        res.status(500).json({ error: 'Failed to fetch teams' });
    }
});


// Add to tblPicksLeft for when someone creates/joins a group for the first time
app.post('/picksLeft', async (req, res, next) => {
    let strGroupID = req.body.groupID;
    let strUserID = req.body.userID;
    let intPicksLeft = 7;
    let intWeek = 1;

    if (strGroupID && strUserID) {
        try {
            const pool = await poolPromise;

            // Prevent initialization after join deadline
            if (await hasJoinDeadlinePassed()) {
                return res.status(403).json({
                    error: "The deadline to join a group has passed"
                });
            }

            // Execute the insert command
            await pool.request()
                .input('UserID', sql.UniqueIdentifier, strUserID)
                .input('GroupID', sql.UniqueIdentifier, strGroupID)
                .input('PicksLeft', sql.Int, intPicksLeft)
                .input('Week', sql.Int, intWeek)
                .query('INSERT INTO tblPicksLeft (UserID, GroupID, PicksLeft, Week) VALUES (@UserID, @GroupID, @PicksLeft, @Week)');

            res.status(201).json({
                message: "success",
                groupID: strGroupID,
                userID: strUserID
            });
        } catch (err) {
            console.error(err);
            res.status(400).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: "Not all parameters provided" });
    }
});

// Get all picksLeft by groupID and userID
app.get('/allPicksLeft', async (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;

    if (strGroupID && strUserID) {
        try {
            const pool = await poolPromise;

            // Execute the query to select all picks left by GroupID and UserID
            const result = await pool.request()
                .input('GroupID', sql.UniqueIdentifier, strGroupID)
                .input('UserID', sql.UniqueIdentifier, strUserID)
                .query('SELECT * FROM tblPicksLeft WHERE GroupID = @GroupID AND UserID = @UserID');

            res.status(200).json({
                message: "success",
                picksLeft: result.recordset
            });
        } catch (err) {
            console.error(err);
            res.status(400).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: "Not all parameters provided" });
    }
});

// Get latest picksLeft by groupID and userID
app.get('/picksLeft', async (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;

    if (strGroupID && strUserID) {
        try {
            const pool = await poolPromise;

            // Execute the query to select PicksLeft for the most recent week by GroupID and UserID
            const result = await pool.request()
                .input('GroupID', sql.UniqueIdentifier, strGroupID)
                .input('UserID', sql.UniqueIdentifier, strUserID)
                .query(`
                    SELECT TOP 1 PicksLeft 
                    FROM tblPicksLeft 
                    WHERE GroupID = @GroupID AND UserID = @UserID 
                    ORDER BY Week DESC
                `);

            res.status(200).json({
                message: "success",
                picksLeft: result.recordset[0]?.PicksLeft || 0
            });
        } catch (err) {
            console.error(err);
            res.status(400).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: "Not all parameters provided" });
    }
});

// Get latest picksLeft by groupID for all users in the group
app.get('/groupPicksLeft', async (req, res, next) => {
    let strGroupID = req.query.groupID;

    if (strGroupID) {
        try {
            const pool = await poolPromise;

            // Execute the query to select PicksLeft for the most recent week for all users in the group
            const result = await pool.request()
                .input('GroupID', sql.UniqueIdentifier, strGroupID)
                .query(`
                    SELECT UserID, PicksLeft
                    FROM tblPicksLeft
                    WHERE GroupID = @GroupID
                    AND Week = (
                        SELECT MAX(Week)
                        FROM tblPicksLeft
                        WHERE GroupID = @GroupID
                    )
                `);
            
                res.status(200).json({
                    message: "success",
                    picksLeft: result.recordset
                })
        } catch (err) {
            console.error(err);
            res.status(400).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: "Not all parameters provided" });
    }
});

app.get('/picksLeftByWeek', async (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;

    if (strGroupID && strUserID) {
        try {
            const pool = await poolPromise;

            // Execute the query to select PicksLeft for all weeks by GroupID and UserID
            const result = await pool.request()
                .input('GroupID', sql.UniqueIdentifier, strGroupID)
                .input('UserID', sql.UniqueIdentifier, strUserID)
                .query(`
                    SELECT Week, PicksLeft 
                    FROM tblPicksLeft 
                    WHERE GroupID = @GroupID AND UserID = @UserID 
                    ORDER BY Week ASC
                `);

            res.status(200).json({
                message: "success",
                picksLeftArray: result.recordset
            });
        } catch (err) {
            console.error(err);
            res.status(400).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: "Not all parameters provided" });
    }
});

// Get the week the last time the user lost a pick
// Get the last week where picks left decreased for all users in the group
app.get('/lastLostWeek', async (req, res, next) => {
    let strGroupID = req.query.groupID;

    if (strGroupID) {
        try {
            const pool = await poolPromise;

            // Execute the query to select the last week where the picks left decreased for each user in the group
            const result = await pool.request()
                .input('GroupID', sql.UniqueIdentifier, strGroupID)
                .query(`
                    WITH RankedPicks AS (
                        SELECT UserID, Week, PicksLeft,
                            ROW_NUMBER() OVER (PARTITION BY UserID ORDER BY Week DESC) AS RowNum
                        FROM tblPicksLeft
                        WHERE GroupID = @GroupID
                    )
                    SELECT UserID, ISNULL((
                        SELECT TOP 1 Week 
                        FROM RankedPicks AS t1
                        WHERE t1.UserID = rp.UserID 
                        AND t1.PicksLeft < (
                            SELECT t2.PicksLeft 
                            FROM RankedPicks AS t2 
                            WHERE t2.UserID = t1.UserID 
                            AND t2.RowNum = t1.RowNum + 1
                        )
                    ), 1) AS LastLostWeek
                    FROM RankedPicks rp
                    WHERE RowNum = 1
                    GROUP BY UserID, PicksLeft
                `);

            res.status(200).json({
                message: "success",
                lastLostWeekData: result.recordset
            });
        } catch (err) {
            console.error(err);
            res.status(400).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: "GroupID not provided" });
    }
});


// Get first game of the year
app.get('/firstGame', async (req, res, next) => {
    try {
        const gamesData = await getAllGames();
        res.status(200).json(gamesData[0]);
    } catch (error) {
        console.error('Error fetching first game:', error);
        res.status(500).json({ error: 'Failed to fetch the first game' });
    }
});

// Get the year
app.get('/year', (req, res, next) => {
    res.status(200).json({
        message:"success",
        year:year
    })
});

// Get all team logos
app.get('/teamLogos', (req, res) => {
    res.status(200).json({
        message: "success",
        teamLogos: getAllTeamLogos()
    });
});

// Get team logo by team name
app.get('/teamLogo', (req, res) => {
    let teamName = req.query.teamName;
    getTeamLogo(teamName).then(logo => {
        res.status(200).json({
            message: "success",
            teamLogo: logo
        });
    }).catch(err => {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch team logo' });
    });
})

// Get team logo by id
app.get('/teamLogoByID', (req, res) => {
    let teamID = req.query.teamID;
    getTeamLogoByID(teamID).then(logo => {
        res.status(200).json({
            message: "success",
            teamLogo: logo
        });
    }).catch(err => {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch team logo' });
    });
})

// Get spreads for the week
app.get('/weeklySpreads', async (req, res, next) => {
    try {
        const spreadsData = await getSpreads(currentFootballWeekNumber);
        res.status(200).json({
            message: "success",
            spreads: spreadsData
        });
    } catch (error) {
        console.error('Error fetching spreads:', error);
        res.status(500).json({ error: 'Failed to fetch spreads' });
    }
});

/*
    Endpoints for dashboard data
*/

// Get this weeks standings for a specific group (Includes positional changes from last week)
/*
    Returned Object Example:
    {
        GroupID: "group-id",
        GroupName: "group-name",
        Week: current-week-number,
        PreviousWeek: previous-week-number,
        MemberCount: number-of-members-in-group,
        HasStandings: true/false,
        Standings: [
            {
                UserID: "user-id",
                Username: "user-name",
                Position: current-position,
                PreviousPosition: previous-position,
                PositionChange: position-change,
                PicksLeft: picks-left,
                LastLostWeek: last-week-user-lost-a-pick,
            }
        ]
    }
*/
app.get('/dashboard/currentStandingsByGroup', async (req, res, next) => {
    try {
        const { groupID } = req.query;

        if (!groupID) {
            return res.status(400).json({
                error: 'groupID is required'
            });
        }

        /*
            1. Get group information + member count
        */
        const groupInfo = await dbGet(`
            SELECT
                g.GroupID,
                g.GroupName,
                COUNT(gm.UserID) AS MemberCount
            FROM tblGroups g
            LEFT JOIN tblGroupMembers gm
                ON gm.GroupID = g.GroupID
            WHERE g.GroupID = @param1
            GROUP BY
                g.GroupID,
                g.GroupName
        `, [groupID]);

        if (!groupInfo) {
            return res.status(404).json({
                error: 'Group not found'
            });
        }


        /*
            2. Get the two most recent finalized
               standings weeks for this group
        */
        const weeks = await dbGetAll(`
            SELECT DISTINCT TOP 2
                Week
            FROM tblStandingsHistory
            WHERE GroupID = @param1
            ORDER BY Week DESC
        `, [groupID]);

        const currentWeek =
            weeks[0]?.Week ?? null;

        const previousWeek =
            weeks[1]?.Week ?? null;


        /*
            No standings have been generated yet.
        */
        if (currentWeek === null) {
            return res.json({
                GroupID: groupInfo.GroupID,
                GroupName: groupInfo.GroupName,

                Week: null,
                PreviousWeek: null,

                MemberCount: groupInfo.MemberCount,

                HasStandings: false,

                Standings: []
            });
        }


        /*
            3. Retrieve current standings plus the
               previous position for each user.

            The LEFT JOIN means Week 2 will still
            work even though there is no previous
            standings snapshot.
        */
        const rows = await dbGetAll(`
            SELECT
                currentStanding.UserID,
                gm.Username,

                currentStanding.Position,
                previousStanding.Position
                    AS PreviousPosition,

                currentStanding.PicksLeft,
                currentStanding.LastPickLostWeek

            FROM tblStandingsHistory currentStanding

            INNER JOIN tblGroupMembers gm
                ON gm.UserID = currentStanding.UserID
                AND gm.GroupID = currentStanding.GroupID

            LEFT JOIN tblStandingsHistory previousStanding
                ON previousStanding.UserID =
                    currentStanding.UserID
                AND previousStanding.GroupID =
                    currentStanding.GroupID
                AND previousStanding.Week =
                    @param3

            WHERE currentStanding.GroupID =
                @param1

              AND currentStanding.Week =
                @param2

            ORDER BY
                currentStanding.Position,
                gm.Username
        `, [
            groupID,
            currentWeek,
            previousWeek
        ]);


        /*
            4. Add PositionChange
        */
        const standings = rows.map(row => {
            const previousPosition =
                row.PreviousPosition ?? null;

            const positionChange =
                previousPosition === null
                    ? null
                    : previousPosition -
                      row.Position;

            return {
                UserID: row.UserID,
                Username: row.Username,

                Position: row.Position,
                PreviousPosition:
                    previousPosition,
                PositionChange:
                    positionChange,

                PicksLeft: row.PicksLeft,
                LastPickLostWeek:
                    row.LastPickLostWeek
            };
        });


        /*
            5. Final response
        */
        return res.json({
            GroupID: groupInfo.GroupID,
            GroupName: groupInfo.GroupName,

            Week: currentWeek,
            PreviousWeek: previousWeek,

            MemberCount: groupInfo.MemberCount,

            HasStandings: true,

            Standings: standings
        });

    } catch (error) {
        console.error(
            'Error getting dashboard standings:',
            error
        );

        return res.status(500).json({
            error: 'Failed to get standings'
        });
    }
})

// Get all standings for an user for a specific group
/*
    Returned Object Example:
    {
        UserID: "user-id",
        GroupID: "group-id",
        MemberCount: number-of-members-in-group,
        History: [
            {
                Week: week-number,
                Position: position,
                PicksLeft: picks-left
            }
        ]    
    }
*/
app.get('/dashboard/allStandingsByUser', async (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;

    if (!strGroupID || !strUserID) {
        return res.status(400).json({ error: "GroupID and UserID are required" });
    }

    // First get all standings for the user in the group
    try {
        // Verify the user belongs to the group
        const member = await dbGet(`
            SELECT UserID
            FROM tblGroupMembers
            WHERE GroupID = @param1
              AND UserID = @param2
        `, [
            strGroupID,
            strUserID
        ]);

        if (!member) {
            return res.status(404).json({
                error: "User is not a member of this group"
            });
        }

        const groupInfo = await dbGet(`
            SELECT COUNT(*) AS MemberCount
            FROM tblGroupMembers
            WHERE GroupID = @param1
        `, [strGroupID]);

        const standings = await dbGetAll(`
            SELECT Week, Position, PicksLeft
            FROM tblStandingsHistory
            WHERE GroupID = @param1 AND UserID = @param2
            ORDER BY Week ASC
        `, [strGroupID, strUserID]);

        // Prepend week 1 to the data with Position 1 and PicksLeft 7
        const history = [
            { Week: 1, Position: 1, PicksLeft: 7 },
            ...standings
        ]

        return res.status(200).json({
            UserID: strUserID,
            GroupID: strGroupID,
            MemberCount: groupInfo.MemberCount,
            History: history
        })

    } catch (error) {
        return res.status(500).json({ error: 'Failed to fetch standings' });
    }
});

/*
    Get a summary of losses for all users in a group

    Returned Object Example:
    {
        GroupID: "group-id",
        Week: current-week-number,
        HasLosses: true/false,
        UsersWithLosses: (int) number of users with losses,
        TotalLostPicks: (int) total number of lost picks in the group,
        Losses: [
            {
                PickedTeam: "team-name",
                PickCount: (int) number of users that lost this pick
            },
            ...
        ]
    }
*/
app.get('/dashboard/groupLossesSummary', async (req, res) => {
    const strGroupID = req.query.groupID;

    if (!strGroupID) {
        return res.status(400).json({
            error: 'GroupID is required'
        });
    }

    try {
        // ------------------------------------------------
        // 1. Verify group exists
        // ------------------------------------------------
        const group = await dbGet(`
            SELECT GroupID
            FROM tblGroups
            WHERE GroupID = @param1
        `, [strGroupID]);

        if (!group) {
            return res.status(404).json({
                error: 'Group not found'
            });
        }


        // ------------------------------------------------
        // 2. Find latest finalized standings week
        // ------------------------------------------------
        const latestStandings = await dbGet(`
            SELECT MAX(Week) AS Week
            FROM tblStandingsHistory
            WHERE GroupID = @param1
        `, [strGroupID]);


        // No week has been processed yet
        if (
            !latestStandings ||
            latestStandings.Week === null
        ) {
            return res.status(200).json({
                GroupID: strGroupID,
                Week: null,
                HasLosses: false,
                UsersWithLosses: 0,
                TotalLostPicks: 0,
                Losses: []
            });
        }


        /*
            Example:

            Week 1 PicksLeft = starting Week 1 picks
            Week 2 PicksLeft = picks remaining after Week 1

            Therefore, if latest standings are Week 2,
            the processed week was Week 1.
        */
        const afterWeek =
            Number(latestStandings.Week);

        const processedWeek =
            afterWeek - 1;


        // ------------------------------------------------
        // 3. Calculate picks lost using PicksLeft snapshots
        // ------------------------------------------------
        const lossesSummary = await dbGet(`
            SELECT
                COUNT(
                    CASE
                        WHEN Previous.PicksLeft > CurrentWeek.PicksLeft
                        THEN 1
                    END
                ) AS UsersWithLosses,

                COALESCE(
                    SUM(
                        CASE
                            WHEN Previous.PicksLeft > CurrentWeek.PicksLeft
                            THEN Previous.PicksLeft - CurrentWeek.PicksLeft
                            ELSE 0
                        END
                    ),
                    0
                ) AS TotalLostPicks

            FROM tblPicksLeft AS Previous

            INNER JOIN tblPicksLeft AS CurrentWeek
                ON Previous.UserID = CurrentWeek.UserID
               AND Previous.GroupID = CurrentWeek.GroupID

            WHERE Previous.GroupID = @param1
              AND Previous.Week = @param2
              AND CurrentWeek.Week = @param3
        `, [
            strGroupID,
            processedWeek,
            afterWeek
        ]);


        // ------------------------------------------------
        // 4. Determine which teams caused losses
        // ------------------------------------------------
        const lossesBreakdown = await dbGetAll(`
            SELECT
                PickedTeam,
                COUNT(*) AS PickCount

            FROM tblSelections

            WHERE GroupID = @param1
              AND Week = @param2
              AND selection_correct = 0

            GROUP BY PickedTeam

            ORDER BY
                PickCount DESC,
                PickedTeam ASC
        `, [
            strGroupID,
            processedWeek
        ]);


        // ------------------------------------------------
        // 5. Build response
        // ------------------------------------------------
        const usersWithLosses =
            Number(
                lossesSummary?.UsersWithLosses ?? 0
            );

        const totalLostPicks =
            Number(
                lossesSummary?.TotalLostPicks ?? 0
            );

        return res.status(200).json({
            GroupID: strGroupID,

            Week: processedWeek,

            HasLosses:
                totalLostPicks > 0,

            UsersWithLosses:
                usersWithLosses,

            TotalLostPicks:
                totalLostPicks,

            Losses:
                lossesBreakdown ?? []
        });

    } catch (error) {
        console.error(
            'Error fetching group losses summary:',
            error
        );

        return res.status(500).json({
            error: 'Failed to fetch losses summary'
        });
    }
});



/*
    Updating Week Number Automatically Each Monday
*/

const cron = require('node-cron');
const fetch = require('node-fetch');

let year = new Date().getFullYear();
let currentFootballWeekNumber = 2;

/*
    Functionality to change the year on July 1st and delete database entries for tblPicksLeft, tblSelections, tblGroupMembers, and then tblGroups
*/
function scheduleYearUpdate() {
    // Schedule a job to run every year on July 1st at midnight
    schedule.scheduleJob('0 0 1 7 *', function() {
        let currentYear = new Date().getFullYear();
        year = currentYear;
        //deleteDatabaseEntries();
    });
}

// Run the function to schedule the year update
scheduleYearUpdate();

// To manually delete all database entries
//deleteDatabaseEntries();

async function deleteDatabaseEntries() {
    try {
        const pool = await poolPromise;

        // Delete from tblPicksLeft
        await pool.request().query("DELETE FROM tblPicksLeft");

        // Delete from tblSelections
        await pool.request().query("DELETE FROM tblSelections");

        // Delete from tblGroupMembers
        await pool.request().query("DELETE FROM tblGroupMembers");

        // Delete from tblGroups
        await pool.request().query("DELETE FROM tblGroups");

        // Delete from tblSessions
        await pool.request().query("DELETE FROM tblSessions");

        console.log("All database entries deleted successfully.");
    } catch (err) {
        console.error("Error deleting database entries:", err);
    }
}

async function dbGetAll(query, params = []) {
    try {
        const pool = await poolPromise;
        const request = pool.request();

        params.forEach((param, index) => {
            request.input(`param${index + 1}`, param);
        });

        const result = await request.query(query);
        return result.recordset;
    } catch (error) {
        console.error('Error executing dbGetAll:', error);
        throw error;
    }
}

async function dbGet(query, params = []) {
    try {
        const pool = await poolPromise;
        const request = pool.request();

        params.forEach((param, index) => {
            request.input(`param${index + 1}`, param);
        });

        const result = await request.query(query);
        return result.recordset[0];
    } catch (error) {
        console.error('Error executing dbGet:', error);
        throw error;
    }
}

async function dbRun(query, params = []) {
    try {
        const pool = await poolPromise;
        const request = pool.request();

        params.forEach((param, index) => {
            request.input(`param${index + 1}`, param);
        });

        await request.query(query);
    } catch (error) {
        console.error('Error executing dbRun:', error);
        throw error;
    }
}

async function getAllGames() {
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=${year}&seasonType=regular&classification=fbs`;

    try {
        const response = await fetch(apiEndpoint, {
            method: 'GET',
            headers: {
                'accept': 'application/json',
                'Authorization': 'Bearer sKcweXypMseAJKc7yESIcdyMn4E5T2I0Oese0lKFWtNUmuhxmEB5O6CAMYotHDr8'
            }
        });
        return await response.json();
    } catch (error) {
        console.error('Error fetching data:', error);
        throw error;
    }
}

function getFootballWeekNumber(games) {
    const currentDate = new Date();

    // Sort games by startDate to ensure they are in chronological order
    games.sort((a, b) => new Date(a.startDate) - new Date(b.startDate));

    for (let i = 0; i < games.length; i++) {
        const gameDate = new Date(games[i].startDate);
        const nextGameDate = i + 1 < games.length ? new Date(games[i + 1].startDate) : null;

        // If the current date is before the next game's date or there is no next game,
        // and after or equal to the current game's date, return the current week
        if (currentDate <= gameDate && (nextGameDate === null || currentDate < nextGameDate)) {
            return games[i].week;
        }
    }

    // If the current date is after the last game's date, return the last game's week
    if (currentDate > new Date(games[games.length - 1].startDate)) {
        return games[games.length - 1].week;
    }

    // Default return in case no other conditions are met (shouldn't happen)
    return 1;
}


async function getWeekData() {
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=${year}&week=${currentFootballWeekNumber}&seasonType=regular&classification=fbs`;

    try {
        const response = await fetch(apiEndpoint, {
            method: 'GET',
            headers: {
                'accept': 'application/json',
                'Authorization': 'Bearer sKcweXypMseAJKc7yESIcdyMn4E5T2I0Oese0lKFWtNUmuhxmEB5O6CAMYotHDr8'
            }
        });
        return await response.json();
    } catch (error) {
        console.error('Error fetching data:', error);
        throw error;
    }
}

async function getMembers(weekNumber, groupID) {
    try {
        const members = await dbGetAll("SELECT * FROM tblGroupMembers WHERE GroupID = @param1", [groupID]);

        for (let user of members) {
            await getIncorrectPicks(weekNumber, user.UserID, user.GroupID);
        }
    } catch (err) {
        console.error('Error in getMembers:', err);
    }
}

async function getIncorrectPicks(weekNumber, userID, groupID) {
    try {
        const selections = await dbGetAll(
            "SELECT * FROM tblSelections WHERE GroupID = @param1 AND UserID = @param2 AND Week = @param3",
            [groupID, userID, weekNumber]
        );
        let numIncorrectPicks = selections.filter(selection => selection.selection_correct === 0).length;

        const res = await dbGet(
            "SELECT TOP 1 * FROM tblPicksLeft WHERE GroupID = @param1 AND UserID = @param2 ORDER BY Week DESC",
            [groupID, userID]
        );

        numIncorrectPicks += res.PicksLeft - selections.length;
        await addRowToPicksLeft(weekNumber, groupID, userID, res.PicksLeft - numIncorrectPicks);
    } catch (err) {
        console.error('Error in getIncorrectPicks:', err);
    }
}

async function addRowToPicksLeft(weekNumber, groupID, userID, picksLeft) {
    try {
        await dbRun(
            "INSERT INTO tblPicksLeft (UserID, GroupID, PicksLeft, Week) VALUES (@param1, @param2, @param3, @param4)",
            [userID, groupID, picksLeft, weekNumber + 1]
        );
    } catch (err) {
        console.error('Error in addRowToPicksLeft:', err);
    }
}

async function checkCorrectPick(row, data) {
    const pickedTeam = row.PickedTeam.split(" {")[0];
    const correctPick = pickedTeam === data.homeTeam
        ? data.homePoints > data.awayPoints
        : data.awayPoints > data.homePoints;

    await updateSelection(row, correctPick ? 1 : 0);
}

async function updateSelection(row, correctPick) {
    try {
        await dbRun(
            "UPDATE tblSelections SET selection_correct = @param1 WHERE UserID = @param2 AND GroupID = @param3 AND GameID = @param4 AND Week = @param5",
            [correctPick, row.UserID, row.GroupID, row.GameID, row.Week]
        );
    } catch (err) {
        console.error('Error in updateSelection:', err);
    }
}

async function getLastWeekData() {
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=${year}&seasonType=regular&week=${currentFootballWeekNumber - 1}`;

    try {
        const response = await fetch(apiEndpoint, {
            method: 'GET',
            headers: {
                'accept': 'application/json',
                'Authorization': 'Bearer sKcweXypMseAJKc7yESIcdyMn4E5T2I0Oese0lKFWtNUmuhxmEB5O6CAMYotHDr8'
            }
        });
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error('Error fetching last week data:', error);
        throw error;
    }
}

async function getGameData(gameID) {
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=${year}&seasonType=regular&id=${gameID}`;

    try {
        const response = await fetch(apiEndpoint, {
            method: 'GET',
            headers: {
                'accept': 'application/json',
                'Authorization': 'Bearer sKcweXypMseAJKc7yESIcdyMn4E5T2I0Oese0lKFWtNUmuhxmEB5O6CAMYotHDr8'
            }
        });
        return await response.json();
    } catch (error) {
        console.error(`Error fetching data for game ID ${gameID}:`, error);
        throw error;
    }
}

async function getTeams(year) {
    const apiEndpoint = `https://api.collegefootballdata.com/teams/fbs?year=${year}`;

    try {
        const response = await fetch(apiEndpoint, {
            method: 'GET',
            headers: {
                'accept': 'application/json',
                'Authorization': 'Bearer sKcweXypMseAJKc7yESIcdyMn4E5T2I0Oese0lKFWtNUmuhxmEB5O6CAMYotHDr8'
            }
        });
        return await response.json();
    } catch (error) {
        console.error('Error fetching teams data:', error);
        throw error;
    }
}

// Get games for a specific week
async function getGamesForWeek(week) {
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=${year}&seasonType=regular&week=${week}`;
    const resp = await fetch(apiEndpoint, {
        method: 'GET',
        headers: { accept: 'application/json', Authorization: 'Bearer sKcweXypMseAJKc7yESIcdyMn4E5T2I0Oese0lKFWtNUmuhxmEB5O6CAMYotHDr8' }
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status} for week=${week}`);
    return resp.json();
}

async function getStartingPicksLeft(userID, groupID, week) {
    const row = await dbGet(
        `SELECT PicksLeft
         FROM tblPicksLeft
         WHERE UserID=@param1
           AND GroupID=@param2
           AND Week=@param3`,
        [
            userID,
            groupID,
            week
        ]
    );

    if (row) {
        return row.PicksLeft;
    }

    // Week 1 always starts with 7
    if (week === 1) {
        return 7;
    }

    throw new Error(
        `Missing PicksLeft row for user=${userID}, ` +
        `group=${groupID}, week=${week}`
    );
}

function getUnresolvedSelections(bundle) {
    return bundle.plans.flatMap(
        plan =>
            plan.updates
                .filter(
                    update =>
                        update.correctPick == null
                )
                .map(update => ({
                    UserID:
                        plan.userID,

                    GroupID:
                        plan.groupID,

                    GameID:
                        update.row.GameID,

                    PickedTeam:
                        update.row.PickedTeam,

                    Reason:
                        update.reason || 'Unknown'
                }))
    );
}

async function calculateGroupStandings(groupID, week, tx = null) {
    let result;

    const query = `
        SELECT
            gm.UserID,
            gm.Username,
            pl.PicksLeft,

            (
                SELECT MAX(s.Week)
                FROM tblSelections s
                WHERE s.UserID = gm.UserID
                  AND s.GroupID = gm.GroupID
                  AND s.selection_correct = 0
                  AND s.Week < @wk
            ) AS LastPickLostWeek

        FROM tblGroupMembers gm

        LEFT JOIN tblPicksLeft pl
            ON pl.UserID = gm.UserID
            AND pl.GroupID = gm.GroupID
            AND pl.Week = @wk

        WHERE gm.GroupID = @gid
    `;

    if (tx) {
        result = await new sql.Request(tx)
            .input('gid', sql.UniqueIdentifier, groupID)
            .input('wk', sql.Int, week)
            .query(query);

        result = result.recordset;
    } else {
        result = await dbGetAll(
            `
            SELECT
                gm.UserID,
                gm.Username,
                pl.PicksLeft,

                (
                    SELECT MAX(s.Week)
                    FROM tblSelections s
                    WHERE s.UserID = gm.UserID
                      AND s.GroupID = gm.GroupID
                      AND s.selection_correct = 0
                      AND s.Week < @param2
                ) AS LastPickLostWeek

            FROM tblGroupMembers gm

            LEFT JOIN tblPicksLeft pl
                ON pl.UserID = gm.UserID
                AND pl.GroupID = gm.GroupID
                AND pl.Week = @param2

            WHERE gm.GroupID = @param1
            `,
            [
                groupID,
                week
            ]
        );
    }

    return result;
}

function sortStandings(standings) {
    return standings.sort((a, b) => {
        const aPicks = a.PicksLeft ?? 0;
        const bPicks = b.PicksLeft ?? 0;

        if (bPicks !== aPicks) {
            return bPicks - aPicks;
        }

        const aLastLost = a.LastPickLostWeek ?? 0;
        const bLastLost = b.LastPickLostWeek ?? 0;

        return bLastLost - aLastLost;
    });
}

function assignStandingsPositions(standings) {
    let previous = null;
    let previousPosition = 0;

    return standings.map((standing, index) => {
        const picksLeft =
            standing.PicksLeft ?? 0;

        const lastLost =
            standing.LastPickLostWeek ?? 0;

        let position;

        const tiedWithPrevious =
            previous &&
            picksLeft === (previous.PicksLeft ?? 0) &&
            lastLost === (previous.LastPickLostWeek ?? 0);

        if (tiedWithPrevious) {
            position = previousPosition;
        } else {
            position = index + 1;
        }

        previous = standing;
        previousPosition = position;

        return {
            ...standing,
            Position: position
        };
    });
}

async function getGroupStandings(groupID, week, tx = null) {
    const standings =
        await calculateGroupStandings(
            groupID,
            week,
            tx
        );

    sortStandings(standings);

    return assignStandingsPositions(
        standings
    );
}

async function previewGroupStandings(groupID, week) {
    const standings =
        await getGroupStandings(
            groupID,
            week
        );

    console.table(
        standings.map(s => ({
            Position: s.Position,
            Username: s.Username,
            PicksLeft: s.PicksLeft,
            LastPickLostWeek:
                s.LastPickLostWeek ?? '-'
        }))
    );

    return standings;
}

async function saveGroupStandings(
    tx,
    groupID,
    week
) {
    const standings =
        await getGroupStandings(
            groupID,
            week,
            tx
        );

    // Remove the old snapshot if this week
    // is being rerun.
    await new sql.Request(tx)
        .input(
            'gid',
            sql.UniqueIdentifier,
            groupID
        )
        .input(
            'wk',
            sql.Int,
            week
        )
        .query(`
            DELETE FROM tblStandingsHistory
            WHERE GroupID=@gid
              AND Week=@wk
        `);

    for (const standing of standings) {
        await new sql.Request(tx)
            .input(
                'uid',
                sql.UniqueIdentifier,
                standing.UserID
            )
            .input(
                'gid',
                sql.UniqueIdentifier,
                groupID
            )
            .input(
                'wk',
                sql.Int,
                week
            )
            .input(
                'position',
                sql.Int,
                standing.Position
            )
            .input(
                'picks',
                sql.Int,
                standing.PicksLeft ?? 0
            )
            .input(
                'lastLost',
                sql.Int,
                standing.LastPickLostWeek ?? null
            )
            .query(`
                INSERT INTO tblStandingsHistory
                (
                    UserID,
                    GroupID,
                    Week,
                    Position,
                    PicksLeft,
                    LastPickLostWeek
                )
                VALUES
                (
                    @uid,
                    @gid,
                    @wk,
                    @position,
                    @picks,
                    @lastLost
                )
            `);
    }

    return standings;
}

// Plan ONE user (no writes)
async function planUserChecks(userID, groupID, targetWeek) {
    let processedWeek = targetWeek
        ? Number(targetWeek)
        : undefined;

    if (!processedWeek) {
        const all = await getAllGames();
        const wk = getFootballWeekNumber(all);

        processedWeek = Math.max(1, wk - 1);
    }

    const weekGames =
        await getGamesForWeek(processedWeek);

    const selections = await dbGetAll(
        `SELECT *
         FROM tblSelections
         WHERE Week=@param1
           AND UserID=@param2
           AND GroupID=@param3`,
        [
            processedWeek,
            userID,
            groupID
        ]
    );

    const updates = selections.map(row => {
        const game = weekGames.find(
            g => g.id == row.GameID
        );

        if (!game) {
            return {
                row,
                correctPick: null,
                reason: 'game not found'
            };
        }

        const pickedTeam =
            String(row.PickedTeam).split(" {")[0];

        const correctPick =
            pickedTeam === game.homeTeam
                ? game.homePoints > game.awayPoints
                : game.awayPoints > game.homePoints;

        return {
            row,
            correctPick: correctPick ? 1 : 0
        };
    });

    const baseline =
        await getStartingPicksLeft(
            userID,
            groupID,
            processedWeek
        );

    const incorrect = updates.filter(
        u => u.correctPick === 0
    ).length;

    const missedPicks = Math.max(
        0,
        baseline - selections.length
    );

    const picksLost =
        incorrect + missedPicks;

    const nextWeekPicksLeft = Math.max(
        0,
        baseline - picksLost
    );

    return {
        userID,
        groupID,
        processedWeek,
        baseline,
        selectionCount: selections.length,
        incorrect,
        missedPicks,
        picksLost,
        nextWeekPicksLeft,
        updates
    };
}

// Plan ALL users (no writes)
async function planAllUsersChecks(targetWeek) {
    let processedWeek = targetWeek
        ? Number(targetWeek)
        : undefined;

    if (!processedWeek) {
        const all = await getAllGames();
        const wk = getFootballWeekNumber(all);

        processedWeek = Math.max(1, wk - 1);
    }

    const weekGames =
        await getGamesForWeek(processedWeek);

    // Every user/group relationship should be processed,
    // even if the user made zero selections.
    const allMembers = await dbGetAll(`
        SELECT UserID, GroupID
        FROM tblGroupMembers
    `);

    const allSelections = await dbGetAll(
        `SELECT *
         FROM tblSelections
         WHERE Week=@param1`,
        [processedWeek]
    );

    /*
        Create one map entry for every group member.
        Users with zero selections will simply have rows: []
    */
    const byUser = new Map();

    for (const member of allMembers) {
        const key =
            `${member.UserID}|${member.GroupID}`;

        byUser.set(key, {
            userID: member.UserID,
            groupID: member.GroupID,
            rows: []
        });
    }

    /*
        Add each selection to the corresponding
        user/group combination.
    */
    for (const row of allSelections) {
        const key =
            `${row.UserID}|${row.GroupID}`;

        if (byUser.has(key)) {
            byUser.get(key).rows.push(row);
        }
    }

    const plans = [];

    for (
        const { userID, groupID, rows }
        of byUser.values()
    ) {
        const updates = rows.map(row => {
            const game = weekGames.find(
                g => g.id == row.GameID
            );

            if (!game) {
                return {
                    row,
                    correctPick: null,
                    reason: 'game not found'
                };
            }

            const pickedTeam =
                String(row.PickedTeam)
                    .split(" {")[0];

            const correctPick =
                pickedTeam === game.homeTeam
                    ? game.homePoints > game.awayPoints
                    : game.awayPoints > game.homePoints;

            return {
                row,
                correctPick: correctPick ? 1 : 0
            };
        });

        const baseline =
            await getStartingPicksLeft(
                userID,
                groupID,
                processedWeek
            );

        const incorrect = updates.filter(
            u => u.correctPick === 0
        ).length;

        /*
            If they start with 5 picks but only make
            3 selections, they lose the 2 they didn't make.
        */
        const missedPicks = Math.max(
            0,
            baseline - rows.length
        );

        const picksLost =
            incorrect + missedPicks;

        const nextWeekPicksLeft = Math.max(
            0,
            baseline - picksLost
        );

        plans.push({
            userID,
            groupID,
            processedWeek,
            baseline,
            selectionCount: rows.length,
            incorrect,
            missedPicks,
            picksLost,
            nextWeekPicksLeft,
            updates
        });
    }

    return {
        processedWeek,
        totalUsers: plans.length,
        plans
    };
}

// Undo the first bulk apply for a given week:
// - Reset selection_correct to NULL for Week = week
// - Delete tblPicksLeft rows for Week = week + 1 for affected users
async function undoAllPicksRun(targetWeek) {
    let processedWeek =
        targetWeek
            ? Number(targetWeek)
            : undefined;

    if (!processedWeek) {
        const all = await getAllGames();
        const wk = getFootballWeekNumber(all);

        processedWeek =
            Math.max(1, wk - 1);
    }

    const nextWeek =
        processedWeek + 1;

    const bundle =
        await planAllUsersChecks(
            processedWeek
        );

    const pool =
        await poolPromise;

    const tx =
        new sql.Transaction(pool);

    await tx.begin();

    try {
        await new sql.Request(tx)
            .batch(
                'SET XACT_ABORT ON;'
            );


        // ======================================
        // 1. RESET SELECTION RESULTS
        // ======================================

        await new sql.Request(tx)
            .input(
                'wk',
                sql.Int,
                processedWeek
            )
            .query(`
                UPDATE tblSelections
                SET selection_correct = NULL
                WHERE Week = @wk
            `);


        // ======================================
        // 2. DELETE NEXT WEEK'S PICKS LEFT
        // ======================================

        for (const p of bundle.plans) {
            await new sql.Request(tx)
                .input(
                    'uid',
                    sql.UniqueIdentifier,
                    p.userID
                )
                .input(
                    'gid',
                    sql.UniqueIdentifier,
                    p.groupID
                )
                .input(
                    'wk',
                    sql.Int,
                    nextWeek
                )
                .query(`
                    DELETE FROM tblPicksLeft
                    WHERE UserID = @uid
                      AND GroupID = @gid
                      AND Week = @wk
                `);
        }


        // ======================================
        // 3. DELETE NEXT WEEK'S STANDINGS
        // ======================================

        const groupIDs = [
            ...new Set(
                bundle.plans.map(
                    p => p.groupID
                )
            )
        ];

        for (const groupID of groupIDs) {
            await new sql.Request(tx)
                .input(
                    'gid',
                    sql.UniqueIdentifier,
                    groupID
                )
                .input(
                    'wk',
                    sql.Int,
                    nextWeek
                )
                .query(`
                    DELETE FROM tblStandingsHistory
                    WHERE GroupID = @gid
                      AND Week = @wk
                `);
        }


        // ======================================
        // 4. COMMIT UNDO
        // ======================================

        await tx.commit();

        console.log(
            `🔁 Undo complete:`
        );

        console.log(
            ` - Week ${processedWeek} selections reset`
        );

        console.log(
            ` - Week ${nextWeek} PicksLeft deleted`
        );

        console.log(
            ` - Week ${nextWeek} standings deleted`
        );

    } catch (e) {
        await tx.rollback();

        console.error(
            'Undo failed, rolled back:',
            e.message || e
        );

        throw e;
    }
}

async function commitAllUsersChecks(planBundle) {
    const {
        processedWeek,
        plans
    } = planBundle;

    const nextWeek = processedWeek + 1;

    const pool = await poolPromise;
    const tx = new sql.Transaction(pool);

    let currentStep = 'starting transaction';

    await tx.begin();

    try {
        currentStep = 'enabling XACT_ABORT';

        await new sql.Request(tx)
            .batch('SET XACT_ABORT ON;');


        // ======================================
        // 1. UPDATE SELECTION RESULTS
        // ======================================

        currentStep = 'updating selection results';

        for (const p of plans) {
            for (const u of p.updates) {
                if (u.correctPick == null) {
                    continue;
                }

                await new sql.Request(tx)
                    .input(
                        'sel',
                        sql.Int,
                        u.correctPick
                    )
                    .input(
                        'uid',
                        sql.UniqueIdentifier,
                        u.row.UserID
                    )
                    .input(
                        'gid',
                        sql.UniqueIdentifier,
                        u.row.GroupID
                    )
                    .input(
                        'game',
                        sql.Int,
                        u.row.GameID
                    )
                    .input(
                        'wk',
                        sql.Int,
                        u.row.Week
                    )
                    .query(`
                        UPDATE tblSelections
                        SET selection_correct = @sel
                        WHERE UserID = @uid
                          AND GroupID = @gid
                          AND GameID = @game
                          AND Week = @wk
                    `);
            }
        }


        // ======================================
        // 2. WRITE NEXT WEEK'S PICKS LEFT
        // ======================================

        currentStep = 'writing next week picks left';

        for (const p of plans) {
            await new sql.Request(tx)
                .input(
                    'uid',
                    sql.UniqueIdentifier,
                    p.userID
                )
                .input(
                    'gid',
                    sql.UniqueIdentifier,
                    p.groupID
                )
                .input(
                    'picks',
                    sql.Int,
                    p.nextWeekPicksLeft
                )
                .input(
                    'wk',
                    sql.Int,
                    nextWeek
                )
                .query(`
                    IF EXISTS (
                        SELECT 1
                        FROM tblPicksLeft
                        WHERE UserID = @uid
                          AND GroupID = @gid
                          AND Week = @wk
                    )
                    BEGIN
                        UPDATE tblPicksLeft
                        SET PicksLeft = @picks
                        WHERE UserID = @uid
                          AND GroupID = @gid
                          AND Week = @wk;
                    END
                    ELSE
                    BEGIN
                        INSERT INTO tblPicksLeft
                        (
                            UserID,
                            GroupID,
                            PicksLeft,
                            Week
                        )
                        VALUES
                        (
                            @uid,
                            @gid,
                            @picks,
                            @wk
                        );
                    END
                `);
        }


        // ======================================
        // 3. SAVE NEXT WEEK'S STANDINGS
        // ======================================

        currentStep = 'building group list';

        const groupIDs = [
            ...new Set(
                plans.map(p => p.groupID)
            )
        ];

        currentStep = 'saving next week standings';

        for (const groupID of groupIDs) {
            console.log(
                `Saving standings for group ${groupID}, week ${nextWeek}`
            );

            await saveGroupStandings(
                tx,
                groupID,
                nextWeek
            );
        }


        // ======================================
        // 4. COMMIT EVERYTHING
        // ======================================

        currentStep = 'committing transaction';

        await tx.commit();

        console.log(
            `✅ Committed ${plans.length} user/group records ` +
            `for week ${processedWeek}`
        );

        console.log(
            `✅ Saved standings for ${groupIDs.length} groups ` +
            `for week ${nextWeek}`
        );

    } catch (e) {
        console.error('\n❌ BULK COMMIT FAILED');
        console.error(`Step: ${currentStep}`);
        console.error('Message:', e.message);
        console.error('Code:', e.code);

        if (e.number !== undefined) {
            console.error('SQL Number:', e.number);
        }

        if (e.lineNumber !== undefined) {
            console.error('SQL Line:', e.lineNumber);
        }

        if (e.originalError) {
            console.error(
                'Original Error:',
                e.originalError
            );
        }

        /*
            XACT_ABORT may have already killed the
            transaction. Do not allow rollback()
            to hide the original SQL error.
        */
        try {
            await tx.rollback();

            console.error(
                '↩️ Transaction rolled back.'
            );
        } catch (rollbackError) {
            if (rollbackError.code === 'EABORT') {
                console.error(
                    '↩️ Transaction was already aborted by SQL Server.'
                );
            } else {
                console.error(
                    '❌ Rollback error:',
                    rollbackError
                );
            }
        }

        throw e;
    }
}

// Dry-run entry point: prints what would happen, does NOT write.
async function runGameChecksForSpecificUser(
    userID,
    groupID,
    { week, dryRun = true } = {}
) {
    const plan =
        await planUserChecks(
            userID,
            groupID,
            week
        );

    console.log(
        `\nDRY-RUN — ` +
        `user=${userID}, ` +
        `group=${groupID}, ` +
        `week=${plan.processedWeek}`
    );

    console.table(
        plan.updates.map(u => ({
            GameID: u.row.GameID,
            PickedTeam: u.row.PickedTeam,
            WouldSet_selection_correct:
                u.correctPick,
            Note:
                u.correctPick == null
                    ? (u.reason || '')
                    : ''
        }))
    );

    console.log(
        `Baseline PicksLeft: ${plan.baseline} | ` +
        `Selections: ${plan.selectionCount} | ` +
        `Incorrect: ${plan.incorrect} | ` +
        `Missed: ${plan.missedPicks} | ` +
        `Total Lost: ${plan.picksLost} | ` +
        `Next Week: ${plan.nextWeekPicksLeft}\n`
    );
}

function testStandingsLogic() {
    const testStandings = [
        {
            Username: 'User A',
            PicksLeft: 5,
            LastPickLostWeek: 2
        },
        {
            Username: 'User B',
            PicksLeft: 5,
            LastPickLostWeek: 6
        },
        {
            Username: 'User C',
            PicksLeft: 5,
            LastPickLostWeek: 4
        }
    ];

    sortStandings(testStandings);

    const rankedStandings =
        assignStandingsPositions(testStandings);

    console.table(
        rankedStandings.map(standing => ({
            Position: standing.Position,
            Username: standing.Username,
            PicksLeft: standing.PicksLeft,
            LastPickLostWeek:
                standing.LastPickLostWeek ?? 'Never'
        }))
    );
}



// --- CLI SETUP ---
function startCli() {
    if (!process.stdin.isTTY) return; // Don't start CLI if not in a TTY

    const readline = require('readline');
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        prompt: 'cfb-picks> '
    });

    // Tiny Helpers: Scoped to the CLI
    function printAllUsersPlanSummary(
        bundle,
        sampleCount = 3
    ) {
        console.log(
            `\nPlan - week=${bundle.processedWeek}, ` +
            `users=${bundle.totalUsers}`
        );

        const usersLosingPicks =
            bundle.plans.filter(
                p => p.picksLost > 0
            ).length;

        const totalPicksLost =
            bundle.plans.reduce(
                (total, p) =>
                    total + p.picksLost,
                0
            );

        const usersWithMissedPicks =
            bundle.plans.filter(
                p => p.missedPicks > 0
            ).length;

        console.log(
            `Users losing ≥1 pick: ` +
            `${usersLosingPicks}/${bundle.totalUsers}`
        );

        console.log(
            `Users with missed selections: ` +
            `${usersWithMissedPicks}`
        );

        console.log(
            `Total picks lost: ${totalPicksLost}`
        );

        const sample =
            bundle.plans.slice(
                0,
                sampleCount
            );

        if (sample.length) {
            console.log('\nSample:');

            sample.forEach((p, i) => {
                console.log(
                    ` ${i + 1}. ` +
                    `user=${p.userID} ` +
                    `group=${p.groupID} ` +
                    `baseline=${p.baseline} ` +
                    `selected=${p.selectionCount} ` +
                    `incorrect=${p.incorrect} ` +
                    `missed=${p.missedPicks} ` +
                    `lost=${p.picksLost} ` +
                    `next=${p.nextWeekPicksLeft}`
                );
            });
        }

        console.log('');
    }

    async function confirmPrompt(message) {
        return await new Promise(res => {
            const rl2 = readline.createInterface({ input: process.stdin, output: process.stdout });
            rl2.question(`${message} (y/N) `, a => { rl2.close(); res(/^y(es)?$/i.test(a)); });
        });
    }

    // --- Commands ---
    const commands = {
        // DRY-RUN for one user - NEVER WRITES
        async checkUserPicks(
            userID,
            groupID,
            weekMaybe
        ) {
            if (!userID || !groupID) {
                console.log(
                    'Usage: checkUserPicks ' +
                    '<userID> <groupID> [week]'
                );

                return;
            }

            const week =
                /^\d+$/.test(weekMaybe)
                    ? Number(weekMaybe)
                    : undefined;

            const plan =
                await planUserChecks(
                    userID,
                    groupID,
                    week
                );

            console.log(
                `\nDRY-RUN — ` +
                `user=${userID}, ` +
                `group=${groupID}, ` +
                `week=${plan.processedWeek}`
            );

            if (plan.selectionCount > 0) {
                console.table(
                    plan.updates.map(u => ({
                        GameID: u.row.GameID,
                        PickedTeam:
                            u.row.PickedTeam,

                        WouldSet_selection_correct:
                            u.correctPick,

                        Note:
                            u.correctPick == null
                                ? (u.reason || '')
                                : ''
                    }))
                );
            } else {
                console.log(
                    'No selections were made.'
                );
            }

            console.log(
                `Baseline PicksLeft: ${plan.baseline} | ` +
                `Selections made: ${plan.selectionCount} | ` +
                `Incorrect: ${plan.incorrect} | ` +
                `Missed: ${plan.missedPicks} | ` +
                `Total lost: ${plan.picksLost} | ` +
                `Next week's PicksLeft: ` +
                `${plan.nextWeekPicksLeft}\n`
            );
        },

        // DRY_RUN for all users - PREVIEW ONLY
        async checkAllPicks(weekMaybe) {
            const week =
                /^\d+$/.test(weekMaybe)
                    ? Number(weekMaybe)
                    : undefined;

            const bundle =
                await planAllUsersChecks(week);

            printAllUsersPlanSummary(
                bundle,
                58
            );

            console.log(
                'DRY-RUN only. ' +
                'Use: applyAllPicks [week] to commit.\n'
            );
        },

        // Show Plan -> Confirm -> Write for all users (transaction)
        async applyAllPicks(weekMaybe) {
            const week =
                /^\d+$/.test(weekMaybe)
                    ? Number(weekMaybe)
                    : undefined;


            // 1. Build plan
            const bundle =
                await planAllUsersChecks(week);


            // 2. Show summary
            printAllUsersPlanSummary(
                bundle,
                5
            );


            // 3. Check for unresolved games
            const unresolved =
                getUnresolvedSelections(bundle);

            if (unresolved.length > 0) {
                console.log(
                    `\n❌ Cannot commit. ` +
                    `${unresolved.length} selections ` +
                    `could not be checked.`
                );

                console.table(unresolved);

                return;
            }


            // 4. Show one detailed user
            if (bundle.plans[0]) {
                const p =
                    bundle.plans[0];

                console.log(
                    'First user detailed view:'
                );

                if (p.updates.length) {
                    console.table(
                        p.updates.map(u => ({
                            GameID:
                                u.row.GameID,

                            PickedTeam:
                                u.row.PickedTeam,

                            WouldSet_selection_correct:
                                u.correctPick,

                            Note:
                                u.correctPick == null
                                    ? (u.reason || '')
                                    : ''
                        }))
                    );
                } else {
                    console.log(
                        'No selections for this user.'
                    );
                }

                console.log(
                    `baseline=${p.baseline} ` +
                    `selected=${p.selectionCount} ` +
                    `incorrect=${p.incorrect} ` +
                    `missed=${p.missedPicks} ` +
                    `lost=${p.picksLost} ` +
                    `next=${p.nextWeekPicksLeft}`
                );
            }


            // 5. Confirm
            const ok =
                await confirmPrompt(
                    'Commit these changes to the database?'
                );

            if (!ok) {
                console.log(
                    'Aborted by user.'
                );

                return;
            }


            // 6. Commit exact plan
            await commitAllUsersChecks(bundle);
        },

        async undoAllPicks(weekMaybe) {
            const week =
                /^\d+$/.test(weekMaybe)
                    ? Number(weekMaybe)
                    : undefined;

            console.log(
                '\n⚠️ This will undo the bulk apply for the given week:'
            );

            console.log(
                ' - Reset selection_correct to NULL for that week'
            );

            console.log(
                ' - Delete tblPicksLeft rows for the following week'
            );

            console.log(
                ' - Delete tblStandingsHistory rows for the following week\n'
            );

            const ok =
                await confirmPrompt(
                    `Are you sure you want to proceed` +
                    `${week ? ` for week ${week}` : ''}?`
                );

            if (!ok) {
                console.log(
                    'Aborted by user.'
                );

                return;
            }

            await undoAllPicksRun(week);
        },

        async checkStandings(groupID, weekMaybe) {
            if (!groupID) {
                console.log(
                    'Usage: checkStandings <groupID> [week]'
                );

                return;
            }

            const week =
                /^\d+$/.test(weekMaybe)
                    ? Number(weekMaybe)
                    : undefined;

            if (!week) {
                console.log(
                    'Please provide a standings week.'
                );

                return;
            }

            await previewGroupStandings(
                groupID,
                week
            );
        },

        testStandings() {
            testStandingsLogic();
        },

        help() {
            console.log('\nAvailable commands:');
            console.log(' checkUserPicks <userID> <groupID> [week]  - Dry-run for one user (no writes)');
            console.log(' checkAllPicks [week]                      - Dry-run for all users (no writes)');
            console.log(' applyAllPicks [week]                      - Plan and commit for all users');
            console.log(' undoAllPicks [week]                       - Undo the first bulk apply for a given week');
            console.log(' checkStandings <groupID> <week> - Preview standings for a group');
            console.log(' help                                      - Show this help message');
            console.log(' exit                                      - Exit the CLI');
            console.log(' testStandings                              - Test standings calculation with fake data');
        },

        exit() {
            console.log('Exiting CLI.');
            rl.close();
            try { sql.close(); } catch (e) { /* ignore */ }
            process.exit(0);
        }
    };

    // --- dispatcher ---
    rl.on('line', async (line) => {
        const [cmd, ...args] = line.trim().split(/\s+/);
        const fn = commands[cmd];
        if (!fn) {
            console.log(`Unknown command: ${cmd}. Type 'help' for a list of commands.`);
            return rl.prompt();
        }
        try {
            const out = fn(...args);
            if (out && typeof out.then === 'function') {
                await out;
            }
        } catch (err) {
            console.error('Error executing command:', err || err.message || err.toString());
        } finally {
            rl.prompt();
        }
    });

    // Make ctrl+c behave like 'exit'
    rl.on('SIGINT', () => {
        commands.exit();
    });

    console.log('Welcome to the CFB Picks CLI. Type "help" for a list of commands.');
    rl.prompt();
}


poolPromise.then(() => {
    app.listen(HTTP_PORT, '0.0.0.0', () => {
        console.log(`Server is running on port ${HTTP_PORT}`);
        startCli();
        loadTeamLogos(year)
    });
}).catch(err => {
    console.error('Database connection failed:', err);
    process.exit(1);
});

/*
    Cache weekly games to avoid hitting the api too often.
*/
const GAME_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

let gameCache = {
    year: null,
    week: null,
    games: [],
    fetchedAt: 0
};

// Prevent multiple users from triggering
// simultaneous CFBD refreshes.
let gameCacheRefreshPromise = null;

async function fetchGamesFromCFBD(year, week) {
    const response = await fetch(
        `https://api.collegefootballdata.com/games?year=${year}&week=${week}&seasonType=regular&division=fbs`,
        {
            headers: {
                accept: 'application/json',
                Authorization: `Bearer sKcweXypMseAJKc7yESIcdyMn4E5T2I0Oese0lKFWtNUmuhxmEB5O6CAMYotHDr8`
            }
        }
    );

    if (!response.ok) {
        throw new Error(
            `CFBD request failed: ${response.status}`
        );
    }

    return await response.json();
}

async function getCachedGames(year, week) {
    const currentTime = Date.now();

    const cacheIsValid =
        gameCache.year === Number(year) &&
        gameCache.week === Number(week) &&
        gameCache.games.length > 0 &&
        currentTime - gameCache.fetchedAt < GAME_CACHE_TTL_MS;

    /*
        Cache is still good.

        No CFBD request is made here.
    */
    if (cacheIsValid) {
        return gameCache.games;
    }

    /*
        Another request is already refreshing
        the cache.

        Wait for that request instead of
        making another CFBD request.
    */
    if (gameCacheRefreshPromise) {
        return await gameCacheRefreshPromise;
    }

    console.log(
        `Refreshing game cache for ${year} Week ${week}`
    );

    gameCacheRefreshPromise =
        fetchGamesFromCFBD(year, week);

    try {
        const games =
            await gameCacheRefreshPromise;

        gameCache = {
            year: Number(year),
            week: Number(week),
            games: games,
            fetchedAt: Date.now()
        };

        console.log(
            `Cached ${games.length} games for ${year} Week ${week}`
        );

        return gameCache.games;

    } finally {
        gameCacheRefreshPromise = null;
    }
}


/*
    Get all teams and a logo and store into a lookup table
*/
const teamLogoLookup = new Map();
const teamLogoByID = new Map();



function normalizeTeamName(teamName) {
    return String(teamName ?? '').trim().toLowerCase()
}

async function loadTeamLogos(year) {
    const apiURL = `https://api.collegefootballdata.com`
    const response = await fetch(
        `${apiURL}/teams`,
        {
            headers: {
                accept: 'application/json',
                Authorization: 'Bearer sKcweXypMseAJKc7yESIcdyMn4E5T2I0Oese0lKFWtNUmuhxmEB5O6CAMYotHDr8'
            }
        }
    );

    if (!response.ok) {
        throw new Error(`Failed to fetch team logos: ${response.status} ${response.statusText}`);
    }

    const teams = await response.json();

    if (!Array.isArray(teams) || teams.length === 0) {
        throw new Error('No teams data received from API');
    }

    // Clear existing data before loading new data
    teamLogoLookup.clear();
    teamLogoByID.clear();

    for(const team of teams) {
        const logos = Array.isArray(team.logos) ? team.logos : [];

        // Store the 64x64 logo (At the time was in 9th spot)
        const logoURL = logos[8] || logos[0] || null;

        teamLogoLookup.set(
            normalizeTeamName(team.school),
            logoURL
        );

        if(team.id !== undefined && team.id !== null) {
            teamLogoByID.set(Number(team.id), logoURL);
        }
    }

    return teamLogoLookup.size;
}

function getTeamLogo(teamName) {
    return (
        teamLogoLookup.get(normalizeTeamName(teamName)) ?? null
    );
}

function getTeamLogoByID(teamID) {
    return teamLogoByID.get(number(teamID)) ?? null;
}

function getAllTeamLogos() {
    //Convert map into a regular object before returning
    return Object.fromEntries(teamLogoLookup);
}

async function getSpreads(week) {
    const apiURL = `https://api.collegefootballdata.com`;
    const response = await fetch(
        `${apiURL}/lines?year=${year}&week=${week}&seasonType=regular`,
        {
            headers: {
                accept: 'application/json',
                Authorization: 'Bearer sKcweXypMseAJKc7yESIcdyMn4E5T2I0Oese0lKFWtNUmuhxmEB5O6CAMYotHDr8'
            }
        }
    );

    if (!response.ok) {
        throw new Error(`Failed to fetch spreads: ${response.status} ${response.statusText}`);
    }

    const spreads = await response.json();

    if (!Array.isArray(spreads) || spreads.length === 0) {
        throw new Error('No spreads data received from API');
    }

    return spreads;
}
