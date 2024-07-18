const express = require('express');
const cors = require('cors');
const {v4:uuidv4, stringify} = require('uuid');
const sqlite3 = require('sqlite3').verbose();
const dbSource = "battleship.db";
const bcrypt = require('bcrypt')
const db = new sqlite3.Database(dbSource);
const HTTP_PORT = 8000;
const bodyParser = require('body-parser');

console.log("Listening on port " + HTTP_PORT);
var app = express();
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.text());
app.use(cors());

// Create a new user and return userID
app.post('/users', (req, res, next) => {
    let strFirstName = req.body.firstName;
    let strLastName = req.body.lastName;
    let strUsername = req.body.username;
    let strEmail = req.body.email;
    let strPassword = req.body.password;
    let strUserID = uuidv4();

    if (!strFirstName || !strLastName || !strUsername || !strEmail || !strPassword) {
        res.status(400).send("Missing required fields");
    } else {
        bcrypt.hash(strPassword, 10).then(hash => {
            strPassword = hash;
            let strCommand = "INSERT INTO tblUsers values (?, ?, ?, ?, ?, ?)";
            let arrParameters = [strUserID, strEmail, strUsername, strPassword, strFirstName, strLastName];
            db.run(strCommand, arrParameters, function(err, result) {
                if(err){
                    res.status(400).json({error:err.message});
                } else {
                    res.status(201).json({
                        message: "success",
                        userID: strUserID,
                        email: strEmail
                    })
                }
            });
        }) 
    }
})

// Get userID while verifying user exists
app.get('/users', (req, res, next) => {
    let strEmail = req.query.email;
    let strPassword = req.query.password;
    if(strEmail && strPassword){
        //get hashed password from database for comparison
        let strCommand = "SELECT Password FROM tblUsers WHERE Email = ?"
        let arrParameters = [strEmail];
        db.all(strCommand, arrParameters, (err, rows) => {
            if(rows.length >= 1){
                rows.forEach((row) => {
                    let hashedPass = row.Password;
                    bcrypt.compare(strPassword, hashedPass, function(err, result){
                        if (result) {
                            strCommand = "SELECT UserID FROM tblUsers WHERE Email = ? AND Password = ?"
                            arrParameters = [strEmail, hashedPass];
                            db.all(strCommand, arrParameters, (err, rows) => {
                                if (rows) {
                                    rows.forEach((row) => {
                                        let strUserID = row.UserID;
                                        res.status(201).json({
                                            message:"success",
                                            userID:strUserID
                                        })
                                    })
                                } else {
                                    res.status(400).json({error:err.message});
                                }
                            })
                        } else {
                            res.status(200).json({error:"Invalid Credentials"});
                        }
                    })
                })
            } else {
                res.status(200).json({error:"Invalid Credentials"});
            }
        })
    }
})

app.get('/userID', (req, res, next) => {
    let strSessionID = req.query.SessionID;

    let strCommand = "SELECT UserID FROM tblSessions WHERE SessionID = ?";
    db.get(strCommand, strSessionID, (err, result) => {
        if (result) {
            res.status(201).json({
                message: "success",
                userID: result.UserID
            })
        } else {
            res.status(200).json({error: "Invalid SessionID"});
        }
    })
})

// Create a sessionID and return SessionID
app.post('/sessions', (req, res, next) => {
    let strEmail = req.body.email;
    let strPassword = req.body.password;
    let strSessionID = uuidv4();
    if (strEmail && strPassword){
        let strCommand = "SELECT Password FROM tblUsers WHERE Email = ?"  ;                 //get hashed password from database
        let arrParameters = [strEmail];
        db.all(strCommand, arrParameters, (err, rows) => {
            if (rows) {
                rows.forEach((row) => {
                    let hashedPass = row.Password
                    bcrypt.compare(strPassword, hashedPass, function(err, result){          //used to compare if hashed password would be the normal password
                        if (result) {
                            strCommand = "SELECT UserID FROM tblUsers where Email = ? AND Password= ?"
                            arrParameters = [strEmail, hashedPass]
                            db.all(strCommand, arrParameters, (err, rows) => {
                                if (rows) {
                                    rows.forEach((row) => {
                                        let strUserID = row.UserID;
                                        strCommand = "INSERT INTO tblSessions VALUES(?,?)"
                                        arrParameters = [strSessionID, strUserID]
                                        db.run(strCommand, arrParameters, (err, result) => {
                                            if (err) {
                                                res.status(400).json({error:err.message})
                                            } else {
                                                res.status(201).json({
                                                    message:"success",
                                                    sessionid:strSessionID
                                                })
                                            }
                                        })
                                    })
                                } else {
                                    res.status(400).json({error:err.message});
                                }
                            })
                        } else {
                            res.status(400).json({error:err.message});
                        }
                    })
                })
            } else {
                res.status(400).json({error:err.message});
            }
        })
    } else {
        res.status(400).json({error:"Not all parameters provided"});
    }
})

//Delete SessionID from database
app.delete('/sessions', (req, res, next) => {
    let strSessionID = req.query.SessionID
    let strCommand = "DELETE FROM tblSessions WHERE SessionID = ?";
    let arrParameters = [strSessionID];
    db.run(strCommand, arrParameters, function(err, result){
        if(err){
            res.status(400).json({error:err.message});
        } else {
            res.status(201).json({
                message:"SessionID successfully deleted"
            })
        }
    })
})

app.post('/groups', (req, res, next) => {
    let strGroupName = req.body.groupName;
    let strOwnerID = req.body.ownerID;
    let strOwner;
    let strPassword = req.body.password;
    let strGroupID = uuidv4();
    
    // Only need to hash password if it is not empty
    if (strPassword == '') {
        let strCommand = "SELECT Username FROM tblUsers WHERE UserID = ?";
        let arrParameters = [strOwnerID];
        db.get(strCommand, arrParameters, (err, row) => {
            if (row) {
                strOwner = row.Username;
                strCommand = "INSERT INTO tblGroups VALUES(?, ?, ?, ?, ?)";
                arrParameters = [strGroupID, strGroupName, strOwner, strOwnerID, strPassword];
                db.run(strCommand, arrParameters, function(err, result){
                    if(err){
                        res.status(400).json({error:err.message});
                    } else {
                        res.status(201).json({
                            message:"success",
                            groupID:strGroupID,
                            groupName:strGroupName
                        })
                    }
                })
            } else {
                res.status(400).json({error:err.message});
            }
        })
    } else {
        // get Owner username from tblUsers
        bcrypt.hash(strPassword, 10).then(hash => {
            strPassword = hash;
            let strCommand = "SELECT Username FROM tblUsers WHERE UserID = ?";
            let arrParameters = [strOwnerID];
            db.get(strCommand, arrParameters, (err, row) => {
                if (row) {
                    strOwner = row.Username;
                    strCommand = "INSERT INTO tblGroups VALUES(?, ?, ?, ?, ?)";
                    arrParameters = [strGroupID, strGroupName, strOwner, strOwnerID, strPassword];
                    db.run(strCommand, arrParameters, function(err, result){
                        if(err){
                            res.status(400).json({error:err.message});
                        } else {
                            res.status(201).json({
                                message:"success",
                                groupID:strGroupID,
                                groupName:strGroupName
                            })
                        }
                    })
                } else {
                    res.status(400).json({error:err.message});
                }
            })
        })
    }
})

app.get('/groups', (req, res, next) => {
    let strCommand = "SELECT * FROM tblGroups";
    db.all(strCommand, (err, rows) => {
        if (rows) {
            res.status(200).json(rows);
        } else {
            res.status(400).json({error:err.message});
        }
    })
})

// Get group by groupID
app.get('/groupByID', (req, res, next) => {
    let strGroupID = req.query.groupID;
    
    if(!strGroupID){
        res.status(400).json({error:"Not all parameters provided"});
    } else {
        let strCommand = "SELECT * FROM tblGroups WHERE GroupID = ?";
        let arrParameters = [strGroupID];
        db.get(strCommand, arrParameters, (err, row) => {
            if (row) {
                res.status(200).json(row);
            } else {
                res.status(400).json({error:err.message});
            }
        })
    }
})

// GroupID, GroupName, UserID, Username
app.post('/groupmembers', (req, res, next) => {
    let strGroupID = req.body.groupID;
    let strGroupName = req.body.groupName;
    let strUserID = req.body.userID;
    let strGroupPassword = req.body.groupPassword;
    let strUsername;

    if (!strGroupID || !strGroupName || !strUserID) {
        res.status(400).json({error:'Not all parameters provided'});
    } else {
        //Get hashed group password from database
        let strCommand = "SELECT Password FROM tblGroups WHERE GroupID = ?";
        db.get(strCommand, strGroupID, (err, result) => {
            if (result) {
                let hashedPass = result.Password;
                //if hashed password is empty, add user to group
                if (hashedPass == '') {
                    let strCommand = "SELECT Username FROM tblUsers WHERE UserID = ?";
                    let arrParameters = [strUserID];
                    db.get(strCommand, arrParameters, function(err, result){
                        strUsername = result.Username;
                        strCommand = "INSERT INTO tblGroupMembers VALUES (?, ?, ?, ?)"
                        arrParameters = [strGroupID, strGroupName, strUserID, strUsername];
                        db.run(strCommand, arrParameters, function(err, result){
                            if (err) {
                                res.status(400).json({error:err.message})
                            } else {
                                res.status(201).json({
                                    message:"Member successfully added to the group"
                                })
                            }
                        })
                    })
                } else {    //if hashed password is not empty, compare hashed group password with input password
                    // Compare hashed group password with input password
                    bcrypt.compare(strGroupPassword, hashedPass, function(err, result){
                        // If passwords match, add user to group
                        if (result) {
                            let strCommand = "SELECT Username FROM tblUsers WHERE UserID = ?";
                            let arrParameters = [strUserID];
                            db.get(strCommand, arrParameters, function(err, result){
                                strUsername = result.Username;
                                strCommand = "INSERt INTO tblGroupMembers VALUES (?, ?, ?, ?)"
                                arrParameters = [strGroupID, strGroupName, strUserID, strUsername];
                                db.run(strCommand, arrParameters, function(err, result){
                                    if (err) {
                                        res.status(400).json({error:err.message})
                                    } else {
                                        res.status(201).json({
                                            message:"Member successfully added to the group"
                                        })
                                    }
                                })
                            })
                        } else {
                            res.status(200).json({error:"Invalid Group Password"});
                        }
                    })
                }
            }
        })
    }
});

app.get('/groupmembers', (req, res, next) => {
    let strGroupID = req.query.groupID;

    let strCommand = "SELECT * FROM tblGroupMembers WHERE GroupID = ?"
    let arrParameters = [strGroupID];
    db.all(strCommand, arrParameters, function(err, result){
        if (err) {
            res.status(400).json({error:err.message})
        } else {
            res.status(201).json({
                message:"success",
                members:result
            })
        }
    })
})

// Get groups by UserID
app.get('/groupsByUserID', (req, res, next) => {
    let strUserID = req.query.userID;

    let strCommand = "SELECT * FROM tblGroupMembers WHERE UserID = ?";
    let arrParameters = [strUserID];
    db.all(strCommand, arrParameters, function(err, result){
        if (err) {
            res.status(400).json({error:err.message})
        } else {
            res.status(201).json({
                message:"success",
                groups:result
            })
        }
    })
})

app.get('/groupOwner', (req, res, next) => {
    let strGroupID = req.query.groupID;

    let strCommand = "SELECT OwnerName FROM tblGroups WHERE GroupID = ?";
    let arrParameters = [strGroupID];
    db.get(strCommand, arrParameters, function(err, result){
        if (err) {
            res.status(400).json({error:err.message})
        } else {
            res.status(201).json({
                message:"here",
                owner:result.OwnerName
            })
        }
    })
})

app.post('/picksMade', (req, res, next) => {
    let strGroupID = req.body.groupID;
    let strUserID = req.body.userID;
    let strPick = 'false';
    let intWeek = req.body.week;
    let intPicksLeft = req.body.picksLeft;

    if (strGroupID && strUserID) {
        let strError, error;
        var promise = new Promise((resolve, reject) => {
            let strCommand = "INSERT INTO tblPicksMade VALUES(?, ?, ?, ?)";
            let arrParameters = [intWeek, strUserID, strPick, strGroupID];
            for (let i = 1; i <= intPicksLeft; i++) {
                db.run(strCommand, arrParameters, function(err, result){
                    if (err) {
                        strError = 'error';
                        error = err.message;
                    } else {
                        strError = 'success';
                    }
                })
                if (i == intPicksLeft) resolve();
            }
        })

        promise.then(() => {
            if (strError == 'error') {
                res.status(400).json({error:error})
            } else {
                res.status(201).json({
                    message:"success",
                })
            }
        })
    } else {
        res.status(400).json({error:"Not all parameters provided"});
    }
});

app.get('/picksMade', (req, res, next) => {
    let strGroupID = req.query.groupID;
    let intWeek = req.query.week;
    if (strGroupID && intWeek) {
        let strCommand = "SELECT * FROM tblPicksMade WHERE GroupID = ? AND Week = ?";
        let arrParameters = [strGroupID, intWeek];
        db.all(strCommand, arrParameters, function(err, result){
            if (err) {
                res.status(400).json({error:err.message})
            } else {
                res.status(201).json({
                    message:"success",
                    picks:result
                })
            }
        })
    } else {
        res.status(400).json({error:"Not all parameters provided"});
    }
});

app.get('/weekData', async (req, res, next) => {
    try {
        getWeekData(function(weekData){
            res.status(200).json(weekData);
        });
    } catch (error) {
        next(error);
    }
});

app.get('/weekNumber', (req, res, next) => {
    let strWeekNumber = getFootballWeekNumber(seasonStartDate);
    res.status(200).json({
        message:"success",
        weekNumber:strWeekNumber
    })
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).send('Internal Server Error');
});

/*
    Updating Week Number Automatically Each Monday
*/

const cron = require('node-cron');
const fetch = require('node-fetch');

function getFootballWeekNumber(startDate) {
    const now = new Date();
    const start = new Date(startDate);
    const diff = now - start;
    const oneWeek = 1000 * 60 * 60 * 24 * 7;
    return Math.ceil(diff / oneWeek);
}

const seasonStartDate = '2024-07-16'; //Change this to the start date of the season

function getWeekData(callback) {
    const currentFootballWeekNumber = getFootballWeekNumber(seasonStartDate);
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=2024&week=${currentFootballWeekNumber}&seasonType=regular&division=fbs`;

    fetch(apiEndpoint, {
        method: 'GET',
        headers: {
            'accept': 'application/json',
            'Authorization': 'Bearer sKcweXypMseAJKc7yESIcdyMn4E5T2I0Oese0lKFWtNUmuhxmEB5O6CAMYotHDr8'
        }
    })
    .then(response => response.json())
    .then(data => {
        // Process the data
        callback(data);
    })
    .catch(error => console.error('Error fetching data:', error));
}


app.listen(HTTP_PORT);