const express = require('express');
const cors = require('cors');
const path = require('path');
const {v4: uuidv4, stringify} = require('uuid');
const sql = require('mssql');
const bcrypt = require('bcrypt');
const schedule = require('node-schedule');
const HTTP_PORT = 8080;
const bodyParser = require('body-parser');
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
            res.status(500).json({ error: err.message });
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

// get game start_dtae by gameID
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
let currentFootballWeekNumber;

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
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=${year}&seasonType=regular&division=fbs`;

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
    let weekNumber = 1;

    for (let game of games) {
        const gameDate = new Date(game.start_date);
        if (gameDate <= currentDate && game.week <= 15) {
            weekNumber = game.week;
        }
    }

    const lastGame = games[games.length - 1];
    const lastGameDate = new Date(lastGame.start_date);
    if (currentDate > lastGameDate && lastGame.week === 16) {
        weekNumber = 16;
    }
    
    return weekNumber;
}

async function getWeekData() {
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=${year}&week=${currentFootballWeekNumber}&seasonType=regular&division=fbs`;

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

async function addPicksLeft(weekNumber) {
    try {
        const groups = await dbGetAll("SELECT * FROM tblGroups");

        for (let group of groups) {
            await getMembers(weekNumber, group.GroupID);
        }
    } catch (err) {
        console.error('Error in addPicksLeft:', err);
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

async function checkWinners(weekNumber) {
    try {
        const selections = await dbGetAll("SELECT * FROM tblSelections WHERE Week = @param1", [weekNumber]);
        const gamesData = await getLastWeekData();

        for (let row of selections) {
            const gameData = gamesData.find(game => game.id == row.GameID);
            await checkCorrectPick(row, gameData);
        }
    } catch (err) {
        console.error('Error in checkWinners:', err);
    }
}

async function checkCorrectPick(row, data) {
    const pickedTeam = row.PickedTeam.split(" {")[0];
    const correctPick = pickedTeam === data.home_team
        ? data.home_points > data.away_points
        : data.away_points > data.home_points;

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

async function scheduleChecks() {
    try {
        const gamesData = await getAllGames();
        const weekNumber = getFootballWeekNumber(gamesData);

        currentFootballWeekNumber = weekNumber;
        const lastGameStart = await getLastGameOfWeekStart(gamesData, weekNumber);

        let scheduleRunTime;
        if (!lastGameStart || new Date(lastGameStart) < new Date()) {   // Set to run on the 15th of August if no games are found
            const nextYear = new Date().getFullYear() + 1;
            scheduleRunTime = new Date(nextYear, 7, 15, 0, 0, 0);
        } else {                                                        // Run after the last game is estimated to finish
            scheduleRunTime = new Date(lastGameStart);
            scheduleRunTime.setHours(scheduleRunTime.getHours() + 8);
        }

        console.log(`Scheduled check for: ${scheduleRunTime}`);
        schedule.scheduleJob(scheduleRunTime, async () => {
            await checkWinners(weekNumber - 1);
            await addPicksLeft(weekNumber - 1);
            scheduleChecks();
        });
    } catch (err) {
        console.error('Error scheduling checks:', err);
    }
}

async function getLastGameOfWeekStart(gameData, weekNumber) {
    const gamesForWeek = gameData.filter(game => game.week === weekNumber)
                                  .sort((a, b) => new Date(b.start_date) - new Date(a.start_date));

    return gamesForWeek.length > 0 ? gamesForWeek[0].start_date : null;
}

scheduleChecks();

/*      To manually run the game checks
async function runGameChecks() {
    try {
        // Get all games for the current season
        const gamesData = await getAllGames();

        // Determine the current football week number
        const weekNumber = getFootballWeekNumber(gamesData);
        currentFootballWeekNumber = weekNumber;

        // Check winners for the previous week
        await checkWinners(weekNumber - 1);

        // Add picks left for the previous week
        await addPicksLeft(weekNumber - 1);

    } catch (error) {
        console.error('Error running game checks:', error);
    }
}

runGameChecks();
*/

app.listen(HTTP_PORT);
