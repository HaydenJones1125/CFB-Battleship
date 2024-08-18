const express = require('express');
const cors = require('cors');
const {v4:uuidv4, stringify} = require('uuid');
const sqlite3 = require('sqlite3').verbose();
const dbSource = "battleship.db";
const bcrypt = require('bcrypt')
const schedule = require('node-schedule');
const db = new sqlite3.Database(dbSource);
const HTTP_PORT = 8080;
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

// Send made picks to database
app.post('/selection', (req, res, next) => {
    let strUserID = req.body.userID;
    let strPickedTeam = req.body.pickedTeam;      // Can contain multiple teams
    let strGroupID = req.body.groupID;
    let strGameID = req.body.gameID;              // Can contain multiple gameIDs (same length as pickedTeams)
    let strWeek = req.body.week;
    let strPickNum = req.body.pickNum
    let strSelectionCorrect = null;

    if (strUserID && strPickedTeam && strGroupID && strGameID && strWeek && strPickNum) {
        let strCommand = "INSERT INTO tblSelections VALUES(?, ?, ?, ?, ?, ?, ?)";
        let arrParameters = [strUserID, strPickedTeam, strGroupID, strGameID, strWeek, strPickNum, strSelectionCorrect];
        db.run(strCommand, arrParameters, function(err, result){
            if (err) {
                res.status(400).json({error:err.message})
            } else {
                res.status(201).json({
                    message:"success",
                    userID:strUserID,
                    groupID:strGroupID,
                    week:strWeek,
                    pickNum:strPickNum
                })
            }
        })
    } else {
        res.status(400).json({error:"Not all parameters provided"});
    }
});

//Get selections by groupID and userID
app.get('/selections', (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;

    if (strGroupID && strUserID) {
        let strCommand = "SELECT * FROM tblSelections WHERE GroupID = ? AND UserID = ?";
        let arrParameters = [strGroupID, strUserID];
        db.all(strCommand, arrParameters, function(err, result){
            if (err) {
                res.status(400).json({error:err.message})
            } else {
                res.status(201).json({
                    message:"success",
                    selections:result
                })
            }
        })
    } else {
        res.status(400).json({error:"Not all parameters provided"});
    }
})

// Delete selection by groupID, userID, and gameID
app.delete('/selections', (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;
    let strGameID = req.query.gameID;

    if (strGroupID && strUserID && strGameID) {
        let strCommand = "DELETE FROM tblSelections WHERE GroupID = ? AND UserID = ? AND GameID = ?";
        let arrParameters = [strGroupID, strUserID, strGameID];
        db.run(strCommand, arrParameters, function(err, result){
            if (err) {
                res.status(400).json({error:err.message})
            } else {
                res.status(201).json({
                    message:"success",
                    groupID:strGroupID,
                    userID:strUserID,
                    gameID:strGameID
                })
            }
        })
    } else {
        res.status(400).json({error:"Not all parameters provided"});
    }
})

// Get selections by groupID, userID, and current week
app.get('/selectionsByCurrentWeek', (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;

    if (strGroupID && strUserID) {
        let strCommand = "SELECT * FROM tblSelections WHERE GroupID = ? AND UserID = ? AND Week = ?";
        let arrParameters = [strGroupID, strUserID, currentFootballWeekNumber];
        db.all(strCommand, arrParameters, function(err, result){
            if (err) {
                res.status(400).json({error:err.message})
            } else {
                res.status(201).json({
                    message:"success",
                    selections:result
                })
            }
        })
    } else {
        res.status(400).json({error:"Not all parameters provided"});
    }
});

app.get('/weekData', async (req, res, next) => {
    getWeekData(function(weekData){
        res.status(200).json(weekData);
    });
});

app.get('/weekNumber', (req, res, next) => {
    res.status(200).json({
        message:"success",
        weekNumber:currentFootballWeekNumber
    })
});

// get game start_date by game id
app.get('/gameStartDate', (req, res, next) => {
    let strGameID = req.query.gameID;

    getStartDate(strGameID, function(startDate){
        res.status(200).json(startDate);
    })
});

// get game data by game id
app.get('/gameData', (req, res, next) => {
    let strGameID = req.query.gameID;

    getGameData(strGameID, function(gameData){
        res.status(200).json(gameData);
    });
});

app.get('/teams', (req, res, next) => {
    let year = req.query.year;

    getTeams(year, function(teams){
        res.status(200).json(teams);
    })
});

// Add to tblPicksLeft for when someone creates/joins a group for the first time
app.post('/picksLeft', (req, res, next) => {
    let strGroupID = req.body.groupID;
    let strUserID = req.body.userID;
    let intPicksLeft = 7;
    let intWeek = 1;

    if (strGroupID && strUserID) {
        let strCommand = "INSERT INTO tblPicksLeft VALUES(?, ?, ?, ?)";
        let arrParameters = [strUserID, strGroupID, intPicksLeft, intWeek];
        db.run(strCommand, arrParameters, function(err, result){
            if (err) {
                res.status(400).json({error:err.message})
            } else {
                res.status(201).json({
                    message:"success",
                    groupID:strGroupID,
                    userID:strUserID
                })
            }
        })
    } else {
        res.status(400).json({error:"Not all parameters provided"});
    }
});

// Get all picksLeft by groupID and userID
app.get('/allPicksLeft', (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;

    if (strGroupID && strUserID) {
        let strCommand = "SELECT * FROM tblPicksLeft WHERE GroupID = ? AND UserID = ?";
        let arrParameters = [strGroupID, strUserID];
        db.all(strCommand, arrParameters, function(err, result){
            if (err) {
                res.status(400).json({error:err.message})
            } else {
                res.status(201).json({
                    message:"success",
                    picksLeft:result
                })
            }
        })
    } else {
        res.status(400).json({error:"Not all parameters provided"});
    }
})

// Get latest picksLeft by groupID and userID
app.get('/picksLeft', (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;

    if (strGroupID && strUserID) {
        let strCommand = "SELECT PicksLeft FROM tblPicksLeft WHERE GroupID = ? AND UserID = ? ORDER BY Week DESC LIMIT 1;";
        let arrParameters = [strGroupID, strUserID];
        db.all(strCommand, arrParameters, function(err, result){
            if (err) {
                res.status(400).json({error:err.message})
            } else {
                res.status(201).json({
                    message:"success",
                    picksLeft:result
                })
            }
        })
    } else {
        res.status(400).json({error:"Not all parameters provided"});
    }
})

// Get the week the last time the user lost a pick
app.get('/lastLostWeek', (req, res, next) => {
    let strGroupID = req.query.groupID;
    let strUserID = req.query.userID;

    if (strGroupID && strUserID) {
        let strCommand = "SELECT Week FROM tblPicksLeft AS t1 WHERE GroupID = ? AND UserID = ? AND PicksLeft < (SELECT PicksLeft FROM tblPicksLeft AS t2 WHERE t2.GroupID = t1.GroupID AND t2.UserID = t1.UserID AND t2.Week = t1.Week - 1) ORDER BY Week DESC LIMIT 1;";
        let arrParameters = [strGroupID, strUserID];
        db.all(strCommand, arrParameters, function(err, result){
            if (err) {
                res.status(400).json({error:err.message})
            } else {
                res.status(201).json({
                    message:"success",
                    lastLostWeek:result
                })
            }
        })
    } else {
        res.status(400).json({error:"Not all parameters provided"});
    }
});

app.get('/firstGame', (req, res, next) => {
    getAllGames(function(gamesData){
        res.status(200).json(gamesData[0]);
    });
});

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

let gameData = [];
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

function deleteDatabaseEntries(){
    let strCommand = "DELETE FROM tblPicksLeft"
    db.run(strCommand, function(err, result){
        if (err) {
            console.log(err);
        } else {
            strCommand = "DELETE FROM tblSelections"
            db.run(strCommand, function(err, result){
                if (err) {
                    console.log(err);
                } else {
                    strCommand = "DELETE FROM tblGroupMembers"
                    db.run(strCommand, function(err, result){
                        if (err) {
                            console.log(err);
                        } else {
                            strCommand = "DELETE FROM tblGroups"
                            db.run(strCommand, function(err, result){
                                if (err) {
                                    console.log(err);
                                }
                            })
                        }
                    })
                }
            })
        }
    })
}

// Gets All Games for the Current Season
function getAllGames(callback) {
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=${year}&seasonType=regular&division=fbs`;

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

// Gets Current Football Week Number
function getFootballWeekNumber(games, callback) {
    const currentDate = new Date();   //2023 Weeks (for testing) Week1: "2023-08-26T18:30:00.000Z" Week2: "2023-09-07T23:30:00.000Z" Week3: "2023-09-14T23:30:00.000Z" Week4: "2023-09-21T23:30:00.000Z" Week5: "2023-09-28T23:30:00.000Z" Week6: "2023-10-05T00:00:00.000Z" Week7: "2023-10-10T23:00:00.000Z" Week8: "2023-10-17T23:00:00.000Z"  Week9: "2023-10-24T23:00:00.000Z" Week10: "2023-10-31T23:00:00.000Z" Week11: "2023-11-08T00:00:00.000Z" Week12: "2023-11-15T00:00:00.000Z" Week13: "2023-11-25T17:00:00.000Z" Week14: "2023-12-03T01:00:00.000Z"

    let weekNumber = 1; // Default to week 1

    for (let i = 0; i < games.length; i++) {
        const gameDate = new Date(games[i].start_date);

        // Check if the game date is earlier or equal to the current date and the week is <= 15
        if (gameDate <= currentDate && games[i].week <= 15) {
            weekNumber = games[i].week;
        }
    }

    // After looping through all games, check if the date is after the last game of week 15
    const lastGame = games[games.length - 1];
    const lastGameDate = new Date(lastGame.start_date);
    if (currentDate > lastGameDate && lastGame.week == 16) {
        weekNumber = 16;
    }

    callback(weekNumber);
}

// Gets data for the next week to make picks
function getWeekData(callback) {
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=${year}&week=${currentFootballWeekNumber}&seasonType=regular&division=fbs`;

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

// Gets a specific games start date and time
function getStartDate(gameID, callback) {
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=${year}&seasonType=regular&id=${gameID}`;

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

// Gets data for a specific game
function getGameData(gameID, callback) {
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=${year}&seasonType=regular&id=${gameID}`;

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

// Gets last week data to check if winner was correctly picked
function getLastWeekData(callback) {
    const apiEndpoint = `https://api.collegefootballdata.com/games?year=${year}&seasonType=regular&week=${currentFootballWeekNumber - 1}`;

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

// Start function to add a row to tblPicksLeft
function addPicksLeft(weekNumber){
    // Get all groups from database
    let strCommand = "SELECT * FROM tblGroups";
    db.all(strCommand, function(err, result){
        if (err) {
            console.log(err);
        } else {
            // For each group, get users to check number of correct picks
            result.forEach((group) => {
                let groupID = group.GroupID
                getMembers(weekNumber, groupID);
            })
        }
    });
}

// Function to get all members for a group for use to check incorrect picks
function getMembers(weekNumber, groupID){
    // Get users for each group
    let strCommand = "SELECT * FROM tblGroupMembers where GroupID = ?";
    db.all(strCommand, groupID, function(err, result){
        if (err) {
            console.log(err);
        } else {
            result.forEach((user) => {
                // For each user, check incorrect picks
                getIncorrectPicks(weekNumber, user.UserID, user.GroupID);
            })
        }    
    })
}

// Function to get the number of incorrect picks for a user in a group
function getIncorrectPicks(weekNumber, userID, groupID){
    // Get selections per group/user
    let strCommand = "SELECT * FROM tblSelections WHERE GroupID = ? AND UserID = ? and Week = ?";
    let arrParameters = [groupID, userID, weekNumber];
    db.all(strCommand, arrParameters, function(err, result){
        if (err) {
            console.log(err);
        } else {
            let numIncorrectPicks = 0;
            // For each pick check if it was correct, if incorrect add 1 to numIncorrectPicks
            let promise = new Promise((resolve, reject) => {
                result.forEach((selection) => {
                    // Check if the selection was incorrect (if so add 1 to numIncorrectPicks)
                    if (selection.selection_correct == 0) {
                        numIncorrectPicks++;
                    }
                })
                resolve();
            })
            
            // For each unused pick, add 1 to numIncorrectPicks
            promise.then(() => {
                let strQuery = "SELECT * FROM tblPicksLeft WHERE GroupID = ? AND UserID = ? ORDER BY Week DESC LIMIT 1;"
                arrParameters = [groupID, userID];
                db.get(strQuery, arrParameters, function(err, res){
                    if (err) {
                        console.log(err)
                    } else {
                        // Check if the user has selected all picks by checking if length of the result from the strCommand query is equal to PicksLeft
                        if (result.length == res.PicksLeft) {
                            addRowToPicksLeft(weekNumber, groupID, userID, (res.PicksLeft - numIncorrectPicks));
                        } else {
                            numIncorrectPicks = numIncorrectPicks + res.PicksLeft - result.length;
                            addRowToPicksLeft(weekNumber, groupID, userID, (res.PicksLeft - numIncorrectPicks));
                        }
                    }
                })
            })
        }
    })
}

// End Function to add a row to tblPicksLeft
function addRowToPicksLeft(weekNumber, groupID, userID, picksLeft){
    let strCommand = "INSERT INTO tblPicksLeft VALUES(?, ?, ?, ?)";
    let arrParameters = [userID, groupID, picksLeft, (weekNumber + 1)];
    db.run(strCommand, arrParameters, function(err, result){
        if (err) {
            console.log(err);
        }
    })

}

// Check if winner was correctly picked then update database for each selection
function checkWinners(weekNumber, callback){
    // Get all selections from database for the week
    let strCommand = "SELECT * FROM tblSelections WHERE Week = ?";
    let arrParameters = [weekNumber];
    db.all(strCommand, arrParameters, function(err, result){
        if (err) {
            console.log(err);
        } else {
            let totalSelections = result.length;
            let processedSelections = 0;
            
            getLastWeekData(function(data){
                let gamesData = data;
                // For each selection, check if winner was correctly picked
                result.forEach((row) => {
                    getGameByID(row.GameID, gamesData, function(gameData){
                        checkCorrectPick(row, gameData, function(){
                            processedSelections++;
                            if (processedSelections === totalSelections) {
                                callback();
                            }
                        });
                    });
                });
            })
        }
    })
}

function getGameByID(gameID, gamesData, callback){
    callback(gamesData.find(game => game.id == gameID));
}

// Checks one pick at a time and updates database, used in checkWinners
function checkCorrectPick(row, data, callback){
    // Split the picked team from conference (string comes as "team {confrence}")
    let pickedTeam = row.PickedTeam.split(" {")[0];

    // Check if winner was correctly picked
    let correctPick, pickedTeamScore, otherTeamScore;
    if (pickedTeam == data.home_team){
        pickedTeamScore = data.home_points;
        otherTeamScore = data.away_points;
    } else {
        pickedTeamScore = data.away_points;
        otherTeamScore = data.home_points;
    }

    // Update database with correct pick (1 for correct, 0 for incorrect)
    if (pickedTeamScore > otherTeamScore){
        correctPick = 1;
        updateSelection(row, correctPick, function(){
            callback();
        });
        
    } else {
        correctPick = 0;
        updateSelection(row, correctPick, function(){
            callback();
        });

    }
}

function updateSelection(row, correctPick, callback){
    let strCommand = "UPDATE tblSelections SET selection_correct = ? WHERE UserID = ? AND GroupID = ? AND GameID = ? AND Week = ?";
    let arrParameters = [correctPick, row.UserID, row.GroupID, row.GameID, row.Week];
    db.run(strCommand, arrParameters, function(err, result){
        if (err) {
            console.log(err);
            callback();
        } else {
            callback();
        }
    })
};

/*
    Get all fbs teams for display
*/
function getTeams(year, callback){
    const apiEndpoint = `https://api.collegefootballdata.com/teams/fbs?year=${year}`;

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

// Manually test (just change date in getCollegeFootballWeekNumber)
//getAllGames(function(gamesData){
//    let gameData = gamesData;
//    getFootballWeekNumber(gameData, function(weekNumber){
//        currentFootballWeekNumber = weekNumber;
//       checkWinners((weekNumber - 1), function(){
//            addPicksLeft((weekNumber - 1));
//        });
//    });  
//})

/*
    Functionality to run winner checks and to update week number
*/
function scheduleChecks(){
    getAllGames(function(gamesData){
        let gameData = gamesData;
        getFootballWeekNumber(gameData, function(weekNumber){
            currentFootballWeekNumber = weekNumber;
            getLastGameOfWeekStart(gameData, weekNumber, function(lastGameStart){
                let scheduleRunTime;
                let scheduledCheck;
                
                // Check if lastGameStart is null or in the past, start rerunning function on August 15
                if (!lastGameStart || new Date(lastGameStart) < new Date()) {
                    // Get today's date and set the year to next year, and date to August 15
                    let nextYear = new Date().getFullYear() + 1;
                    scheduleRunTime = new Date(nextYear, 7, 15, 0, 0, 0); // August is month 7 (0-indexed)
                    scheduledCheck = schedule.scheduleJob(scheduleRunTime, function(){
                        scheduleChecks()
                    })
                } else {
                    // Add 6 hours to last game start time to ensure all games are finished
                    scheduleRunTime = new Date(lastGameStart);
                    scheduleRunTime.setTime(scheduleRunTime.getTime() + (6 * 60 * 60 * 1000)); // Add 6 hours
                    scheduledCheck = schedule.scheduleJob(scheduleRunTime, function(){
                        checkWinners((weekNumber - 1), function(){
                            addPicksLeft((weekNumber - 1), function(){
                                scheduleChecks();
                            });   
                        });   
                    });
                }             
            });
        });
    });
}

function getLastGameOfWeekStart(gameData, weekNumber, callback){
    // Filter games by the specified week
    let gamesForWeek = gameData.filter(game => game.week === weekNumber);

    // Sort games by start_date in descending order
    gamesForWeek.sort((a, b) => new Date(b.start_date) - new Date(a.start_date));

    // Return the start_date of the last game, or null if no games found
    callback(gamesForWeek.length > 0 ? gamesForWeek[0].start_date : null);
}

scheduleChecks();

app.listen(HTTP_PORT);