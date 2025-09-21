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
app.post('/users', async (req, res, next) => {
    let strFirstName = req.body.firstName;
    let strLastName = req.body.lastName;
    let strUsername = req.body.username;
    let strEmail = req.body.email;
    let strPassword = req.body.password;
    let strUserID = uuidv4();

    if (!strFirstName || !strLastName || !strUsername || !strEmail || !strPassword) {
        res.status(400).send("Missing required fields");
    } else {
        try {
            const hashedPassword = await bcrypt.hash(strPassword, 10);

            // Use the existing pool connection
            const pool = await poolPromise;

            // Execute the query
            const request = pool.request();
            request.input('UserID', sql.UniqueIdentifier, strUserID);
            request.input('Email', sql.VarChar, strEmail);
            request.input('Username', sql.VarChar, strUsername);
            request.input('Password', sql.VarChar, hashedPassword);
            request.input('FirstName', sql.VarChar, strFirstName);
            request.input('LastName', sql.VarChar, strLastName);

            const result = await request.query(
                `INSERT INTO tblUsers (UserID, Email, Username, Password, FirstName, LastName)
                    VALUES (@UserID, @Email, @Username, @Password, @FirstName, @LastName)`
            );

            res.status(201).json({
                message: "success",
                userID: strUserID,
                email: strEmail
            });
        } catch (err) {
            console.error(err);
            res.status(409).json({ error: err.message });
        }
    }
});

// Get userID while verifying user exists
app.get('/users', async (req, res, next) => {
    let strEmail = req.query.email;
    let strPassword = req.query.password;

    if (strEmail && strPassword) {
        try {
            const pool = await poolPromise;

            // Step 1: Get the hashed password from the database
            const result = await pool.request()
                .input('Email', sql.VarChar, strEmail)
                .query('SELECT Password FROM tblUsers WHERE Email = @Email');

            if (result.recordset.length >= 1) {
                let hashedPass = result.recordset[0].Password;

                // Step 2: Compare the provided password with the hashed password
                bcrypt.compare(strPassword, hashedPass, async function (err, match) {
                    if (err) {
                        return res.status(500).json({ error: 'Server error' });
                    }

                    if (match) {
                        // Step 3: If password matches, retrieve the UserID
                        const userResult = await pool.request()
                            .input('Email', sql.VarChar, strEmail)
                            .input('Password', sql.VarChar, hashedPass)
                            .query('SELECT UserID FROM tblUsers WHERE Email = @Email AND Password = @Password');

                        if (userResult.recordset.length >= 1) {
                            let strUserID = userResult.recordset[0].UserID;
                            res.status(201).json({
                                message: "success",
                                userID: strUserID
                            });
                        } else {
                            res.status(400).json({ error: 'User not found' });
                        }
                    } else {
                        res.status(200).json({ error: "Invalid Credentials" });
                    }
                });
            } else {
                res.status(200).json({ error: "Invalid Credentials" });
            }
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: 'Missing email or password' });
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
    
    try {
        const pool = await poolPromise; // Reuse the existing connection pool
        const result = await pool.request()
            .input('SessionID', sql.UniqueIdentifier, strSessionID) // Use parameterized queries
            .query('SELECT UserID FROM dbo.tblSessions WHERE SessionID = @SessionID');
    
        if (result.recordset.length > 0) {
            res.status(201).json({
                message: "success",
                userID: result.recordset[0].UserID
            });
        } else {
            res.status(201).json({
                message: "Session not found"
            });
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// Create a session and return SessionID
app.post('/sessions', async (req, res, next) => {
    let strEmail = req.body.email;
    let strPassword = req.body.password;
    let strSessionID = uuidv4();

    if (strEmail && strPassword) {
        try {
            const pool = await poolPromise;

            // Step 1: Get the hashed password from the database
            const result = await pool.request()
                .input('Email', sql.VarChar, strEmail)
                .query('SELECT Password FROM tblUsers WHERE Email = @Email');

            if (result.recordset.length > 0) {
                let hashedPass = result.recordset[0].Password;

                // Step 2: Compare the provided password with the hashed password
                const match = await bcrypt.compare(strPassword, hashedPass);

                if (match) {
                    // Step 3: Retrieve the UserID from the database
                    const userResult = await pool.request()
                        .input('Email', sql.VarChar, strEmail)
                        .input('Password', sql.VarChar, hashedPass)
                        .query('SELECT UserID FROM tblUsers WHERE Email = @Email AND Password = @Password');

                    if (userResult.recordset.length > 0) {
                        let strUserID = userResult.recordset[0].UserID;

                        // Step 4: Insert a new session into tblSessions
                        await pool.request()
                            .input('SessionID', sql.UniqueIdentifier, strSessionID)
                            .input('UserID', sql.UniqueIdentifier, strUserID)
                            .query('INSERT INTO tblSessions (SessionID, UserID) VALUES (@SessionID, @UserID)');

                        res.status(201).json({
                            message: "success",
                            sessionid: strSessionID
                        });
                    } else {
                        res.status(400).json({ error: "User not found" });
                    }
                } else {
                    res.status(400).json({ error: "Invalid password" });
                }
            } else {
                res.status(400).json({ error: "Email not found" });
            }
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: "Not all parameters provided" });
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

// Send made picks to database
app.post('/selection', async (req, res, next) => {
    let strUserID = req.body.userID;
    let strPickedTeam = req.body.pickedTeam;
    let strGroupID = req.body.groupID;
    let strGameID = req.body.gameID;
    let strWeek = req.body.week;
    let strPickNum = req.body.pickNum;
    let strSelectionCorrect = null;

    if (strUserID && strPickedTeam && strGroupID && strGameID && strWeek && strPickNum) {
        try {
            const pool = await poolPromise;

            // Execute the insert command
            await pool.request()
                .input('UserID', sql.UniqueIdentifier, strUserID)
                .input('PickedTeam', sql.VarChar, strPickedTeam)
                .input('GroupID', sql.UniqueIdentifier, strGroupID)
                .input('GameID', sql.Int, strGameID)
                .input('Week', sql.Int, strWeek)
                .input('PickNum', sql.Int, strPickNum)
                .input('SelectionCorrect', sql.Bit, strSelectionCorrect)
                .query('INSERT INTO tblSelections (UserID, PickedTeam, GroupID, GameID, Week, PickNum, selection_correct) VALUES (@UserID, @PickedTeam, @GroupID, @GameID, @Week, @PickNum, @SelectionCorrect)');

            res.status(201).json({
                message: "success",
                userID: strUserID,
                groupID: strGroupID,
                week: strWeek,
                pickNum: strPickNum
            });
        } catch (err) {
            console.error(err);
            res.status(400).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: "Not all parameters provided" });
    }
});

// Get selectiosn by groupID and userID
app.get('/selections', async (req, res, next) => {
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

// Delete selection by groupID, userID and gameID
app.delete('/selections', async (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;
    let strGameID = req.query.gameID;

    if (strGroupID && strUserID && strGameID) {
        try {
            const pool = await poolPromise;

            // Execute the delete command
            const result = await pool.request()
                .input('GroupID', sql.UniqueIdentifier, strGroupID)
                .input('UserID', sql.UniqueIdentifier, strUserID)
                .input('GameID', sql.Int, strGameID)
                .query('DELETE FROM tblSelections WHERE GroupID = @GroupID AND UserID = @UserID AND GameID = @GameID');

            if (result.rowsAffected[0] > 0) {
                res.status(200).json({
                    message: "success",
                    groupID: strGroupID,
                    userID: strUserID,
                    gameID: strGameID
                });
            } else {
                res.status(404).json({ error: "Selection not found" });
            }
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: "Not all parameters provided" });
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

/*
    Updating Week Number Automatically Each Monday
*/

const cron = require('node-cron');
const fetch = require('node-fetch');

let year = new Date().getFullYear();
let currentFootballWeekNumber = 5;

/*
    Functionality to change the year on July 1st and delete database entries for tblPicksLeft, tblSelections, tblGroupMembers, and then tblGroups
*/
function scheduleYearUpdate() {
    // Schedule a job to run every year on July 1st at midnight
    schedule.scheduleJob('0 0 1 7 *', function() {
        let currentYear = new Date().getFullYear();
        year = currentYear;
        deleteDatabaseEntries();
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

// Plan ONE user (no writes)
async function planUserChecks(userID, groupID, targetWeek) {
    let lastWeek = targetWeek ? Number(targetWeek) : undefined;
    if (!lastWeek) {
        const all = await getAllGames();
        const wk = getFootballWeekNumber(all);
        lastWeek = Math.max(1, wk - 1);
    }

    const weekGames = await getGamesForWeek(lastWeek);
    const selections = await dbGetAll(
        "SELECT * FROM tblSelections WHERE Week=@param1 AND UserID=@param2 AND GroupID=@param3",
        [lastWeek, userID, groupID]
    );

    const updates = selections.map(row => {
    const game = weekGames.find(g => g.id == row.GameID);
    if (!game) return { row, correctPick: null, reason: 'game not found' };
        const pickedTeam = String(row.PickedTeam).split(" {")[0];
        const correctPick = pickedTeam === game.homeTeam
            ? (game.homePoints > game.awayPoints)
            : (game.awayPoints > game.homePoints);
        return { row, correctPick: correctPick ? 1 : 0 };
    });

    const latest = await dbGet(
        "SELECT TOP 1 PicksLeft, Week FROM tblPicksLeft WHERE GroupID=@param1 AND UserID=@param2 ORDER BY Week DESC",
        [groupID, userID]
    );

    const incorrect = updates.filter(u => u.correctPick === 0).length;
    const baseline = latest ? latest.PicksLeft : 7;
    const nextWeekPicksLeft = Math.max(0, baseline - incorrect);

    return { userID, groupID, lastWeek, baseline, incorrect, nextWeekPicksLeft, updates, selectionCount: selections.length };
}

// Plan ALL users (no writes)
async function planAllUsersChecks(targetWeek) {
    let lastWeek = targetWeek ? Number(targetWeek) : undefined;
    if (!lastWeek) {
        const all = await getAllGames();
        const wk = getFootballWeekNumber(all);
        lastWeek = Math.max(1, wk - 1);
    }

    const weekGames = await getGamesForWeek(lastWeek);
    const allSelections = await dbGetAll("SELECT * FROM tblSelections WHERE Week=@param1", [lastWeek]);

    const byUser = new Map();
    for (const row of allSelections) {
        const key = `${row.UserID}|${row.GroupID}`;
        if (!byUser.has(key)) byUser.set(key, { userID: row.UserID, groupID: row.GroupID, rows: [] });
        byUser.get(key).rows.push(row);
    }

    const plans = [];
    for (const { userID, groupID, rows } of byUser.values()) {
        const updates = rows.map(r => {
            const game = weekGames.find(g => g.id == r.GameID);
            if (!game) return { row: r, correctPick: null, reason: 'game not found' };
            const pickedTeam = String(r.PickedTeam).split(" {")[0];
            const correctPick = pickedTeam === game.homeTeam
                ? (game.homePoints > game.awayPoints)
                : (game.awayPoints > game.homePoints);
            return { row: r, correctPick: correctPick ? 1 : 0 };
        });

        const latest = await dbGet(
            "SELECT TOP 1 PicksLeft FROM tblPicksLeft WHERE GroupID=@param1 AND UserID=@param2 ORDER BY Week DESC",
            [groupID, userID]
        );
        const incorrect = updates.filter(u => u.correctPick === 0).length;
        const baseline = latest ? latest.PicksLeft : 7;
        const nextWeekPicksLeft = Math.max(0, baseline - incorrect);

        plans.push({ userID, groupID, lastWeek, baseline, incorrect, nextWeekPicksLeft, updates });
    }

    return { lastWeek, totalUsers: plans.length, plans };
}

// Undo the first bulk apply for a given week:
// - Reset selection_correct to NULL for Week = week
// - Delete tblPicksLeft rows for Week = week + 1 for affected users
async function undoAllPicksRun(targetWeek) {
  // Derive the week if not provided (same logic as your planners)
  let week = targetWeek ? Number(targetWeek) : undefined;
  if (!week) {
    const all = await getAllGames();
    const wk = getFootballWeekNumber(all);
    week = Math.max(1, wk - 1);
  }

  // Build the same plan you would have applied, so we know which users/groups were touched
  const bundle = await planAllUsersChecks(week);

  const pool = await poolPromise;
  const tx = new sql.Transaction(pool);
  await tx.begin();
  try {
    await new sql.Request(tx).batch('SET XACT_ABORT ON;');

    // 1) Reset all selection_correct to NULL for that week
    await new sql.Request(tx)
      .input('wk', sql.Int, week)
      .query(`
        UPDATE tblSelections
        SET selection_correct = NULL
        WHERE Week = @wk
      `);

    // 2) Delete next week's PicksLeft only for users we planned to touch
    //    (more precise than deleting for the whole table)
    for (const p of bundle.plans) {
      await new sql.Request(tx)
        .input('uid', sql.UniqueIdentifier, p.userID)
        .input('gid', sql.UniqueIdentifier, p.groupID)
        .input('wk',  sql.Int, week + 1)
        .query(`
          DELETE FROM tblPicksLeft
          WHERE UserID = @uid AND GroupID = @gid AND Week = @wk
        `);
    }

    await tx.commit();
    console.log(`🔁 Undo complete: week ${week} selections reset; week ${week + 1} PicksLeft deleted for ${bundle.plans.length} users.`);
  } catch (e) {
    await tx.rollback();
    console.error('Undo failed, rolled back:', e.message || e);
    throw e;
  }
}

async function commitAllUsersChecks(planBundle) {
    const { lastWeek, plans } = planBundle;
    const pool = await poolPromise;
    const tx = new sql.Transaction(pool);
    await tx.begin();
    try {
        await new sql.Request(tx).batch("SET XACT_ABORT ON;");

        // 1) selection_correct updates
        for (const p of plans) {
            for (const u of p.updates) {
                if (u.correctPick == null) continue;
                await new sql.Request(tx)
                    .input('sel', sql.Int, u.correctPick)
                    .input('uid', sql.UniqueIdentifier, u.row.UserID)
                    .input('gid', sql.UniqueIdentifier, u.row.GroupID)
                    .input('game', sql.Int, u.row.GameID)
                    .input('wk', sql.Int, u.row.Week)
                    .query(`
                    UPDATE tblSelections
                    SET selection_correct = @sel
                    WHERE UserID=@uid AND GroupID=@gid AND GameID=@game AND Week=@wk
                    `);
            }
        }

        // 2) next week's PicksLeft inserts (idempotent)
        for (const p of plans) {
            await new sql.Request(tx)
                .input('uid', sql.UniqueIdentifier, p.userID)
                .input('gid', sql.UniqueIdentifier, p.groupID)
                .input('picks', sql.Int, p.nextWeekPicksLeft)
                .input('wk', sql.Int, lastWeek + 1)
                .query(`
                    IF NOT EXISTS (
                    SELECT 1 FROM tblPicksLeft WHERE UserID=@uid AND GroupID=@gid AND Week=@wk
                    )
                    INSERT INTO tblPicksLeft (UserID, GroupID, PicksLeft, Week)
                    VALUES (@uid, @gid, @picks, @wk);
                `);
        }

        await tx.commit();
        console.log(`✅ Committed ${plans.length} users for week ${lastWeek}`);
    } catch (e) {
        await tx.rollback();
        console.error('❌ Rolled back bulk commit:', e.message || e);
        throw e;
    }
}

// Dry-run entry point: prints what would happen, does NOT write.
async function runGameChecksForSpecificUser(userID, groupID, { week, dryRun = true } = {}) {
    const plan = await planUserChecks(userID, groupID, week);

    console.log(`\nDRY-RUN — user=${userID}, group=${groupID}, lastWeek=${plan.lastWeek}`);
    if (plan.selectionCount === 0) {
        console.log('No selections found for that user/group/week.');
    }
    console.table(
    plan.updates.map(u => ({
        GameID: u.row.GameID,
        PickedTeam: u.row.PickedTeam,
        WouldSet_selection_correct: u.correctPick,
        Note: u.correctPick == null ? (u.reason || '') : ''
    }))
    );
    console.log(
        `Baseline PicksLeft: ${plan.baseline} | Incorrect this week: ${plan.incorrect} | ` +
        `Next week's PicksLeft (computed): ${plan.nextWeekPicksLeft}\n`
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
    function printAllUsersPlanSummary(bundle, sampleCount = 3) {
        console.log(`\nPlan - week=${bundle.lastWeek}, users=${bundle.totalUsers}`);
        const drops = bundle.plans.filter(p => p.incorrect > 0).length;
        console.log(`Users with ≥1 incorrect: ${drops}/${bundle.totalUsers}`);

        const sample = bundle.plans.slice(0, sampleCount);
        if (sample.length) {
            console.log('\nSample:');
            sample.forEach((p, i) => {
                console.log(
                    ` ${i+1}. user=${p.userID} group=${p.groupID} ` +
                    `baseline=${p.baseline} incorrect=${p.incorrect} next=${p.nextWeekPicksLeft}`
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
        async checkUserPicks(userID, groupID, weekMaybe) {
            if (!userID || !groupID) {
                console.log('Usage: checkUserPicks <userID> <groupID> [week]');
                return;
            }
            const week = /^\d+$/.test(weekMaybe) ? Number(weekMaybe) : undefined;
            const plan = await planUserChecks(userID, groupID, week);

            console.log(`\nDRY-RUN — user=${userID}, group=${groupID}, lastWeek=${plan.lastWeek}`);
            if (plan.selectionCount === 0) {
                console.log('No selections found for that user/group/week.');
                return;
            }
            console.table(
                plan.updates.map(u => ({
                    GameID: u.row.GameID,
                    PickedTeam: u.row.PickedTeam,
                    WouldSet_selection_correct: u.correctPick,
                    Note: u.correctPick == null ? (u.reason || '') : ''
                }))
            );
            console.log(
                `Baseline PicksLeft: ${plan.baseline} | Incorrect this week: ${plan.incorrect} | ` +
                `Next week's PicksLeft (computed): ${plan.nextWeekPicksLeft}\n`
            );
        },

        // DRY_RUN for all users - PREVIEW ONLY
        async checkAllPicks(weekMaybe) {
            const week = /^\d+$/.test(weekMaybe) ? Number(weekMaybe) : undefined;
            const bundle = await planAllUsersChecks(week);
            printAllUsersPlanSummary(bundle, 58);
            console.log('DRY-RUN only. Use: applyAllPicks [week] to commit.\n');
        },

        // Show Plan -> Confirm -> Write for all users (transaction)
        async applyAllPicks(weekMaybe) {
            const week = /^\d+$/.test(weekMaybe) ? Number(weekMaybe) : undefined;

            // 1) Build Plan (dry-run)
            const bundle = await planAllUsersChecks(week);

            // 2) Show Plan Summary (and one detailed user)
            printAllUsersPlanSummary(bundle, 5);
            if (bundle.plans[0]) {
                const p = bundle.plans[0];
                console.log('First user detailed view:');
                console.table(
                    p.updates.map(u => ({
                        GameID: u.row.GameID,
                        PickedTeam: u.row.PickedTeam,
                        WouldSet_selection_correct: u.correctPick,
                        Note: u.correctPick == null ? (u.reason || '') : ''
                    }))
                );
            }

            // 3) Confirm
            const ok = await confirmPrompt('Commit these changes to the database?');
            if (!ok) {
                console.log('Aborted by user.');
                return;
            }

            // 4) Commit exactly what was planned
            await commitAllUsersChecks(bundle);
        },

        async undoAllPicks(weekMaybe) {
            const week = /^\d+$/.test(weekMaybe) ? Number(weekMaybe) : undefined;

            console.log('\n⚠️  This will undo the first bulk apply for a given week:');
            console.log(' - Reset selection_correct to NULL for that week');
            console.log(' - Delete tblPicksLeft rows for Week = week + 1 for affected users\n');

            const ok = await confirmPrompt(`Are you sure you want to proceed${week ? ` for week ${week}` : ''}?`);
            if (!ok) {
                console.log('Aborted by user.');
                return;
            }

            await undoAllPicksRun(week);
        },

        help() {
            console.log('\nAvailable commands:');
            console.log(' checkUserPicks <userID> <groupID> [week]  - Dry-run for one user (no writes)');
            console.log(' checkAllPicks [week]                      - Dry-run for all users (no writes)');
            console.log(' applyAllPicks [week]                      - Plan and commit for all users');
            console.log(' undoAllPicks [week]                       - Undo the first bulk apply for a given week');
            console.log(' help                                      - Show this help message');
            console.log(' exit                                      - Exit the CLI\n');
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
    app.listen(HTTP_PORT, () => {
        console.log(`Server is running on port ${HTTP_PORT}`);
        startCli();
    });
}).catch(err => {
    console.error('Database connection failed:', err);
    process.exit(1);
});