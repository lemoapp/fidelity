// server.js
const express = require('express');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const router = express.Router();
const cors = require('cors');
const path = require('path');
const cron = require('node-cron');
const fetch = require('node-fetch');
const NEWS_API_URL = 'https://newsapi.org/v2/top-headlines'; // or whatever API endpoint you're using



dotenv.config();

const app = express();
app.use(cors()); // Enable CORS
app.use(router);
app.use(express.json()); // Parse JSON bodies
app.use(express.static(path.join(__dirname)));
app.use(express.static(__dirname));



// MySQL database connection
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

app.post('/api/signup', async (req, res) => {
    const { fullName, email, username, password, referrer } = req.body;

    try {
        // Check if user already exists
        const [existingUser] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        if (existingUser.length > 0) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        // No password hashing - storing password as plain text for now
        const plainPassword = password;

        // Debug: Log the password before storing it
        console.log('Plain text password to be stored:', plainPassword);

        // Insert new user into the database
        await db.query('INSERT INTO users (fullName, email, username, password, referrer, verified) VALUES (?, ?, ?, ?, ?, ?)', 
            [fullName, email, username, plainPassword, referrer, false]);

        // Verify the user was inserted and password saved
        const insertedUser = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        console.log('Inserted user:', insertedUser[0]);

        // Generate OTP and JWT
        const otp = Math.floor(100000 + Math.random() * 900000); // Generates a 6-digit OTP
        const token = jwt.sign({ email, otp }, process.env.JWT_SECRET, { expiresIn: '10m' }); // token valid for 10 minutes

        // Store the OTP in the database
        await db.query('UPDATE users SET otp = ? WHERE email = ?', [otp, email]);

        // Send OTP email using Zoho transporter
        const sendEmail = async (to, subject, htmlContent) => {
            try {
                const transporter = nodemailer.createTransport({
                    host: 'smtp.zoho.com', // Zoho SMTP server
                    port: 465, // SSL port
                    secure: true, // Use SSL
                    auth: {
                        user: process.env.ZOHO_EMAIL_USER, // Your Zoho email
                        pass: process.env.ZOHO_EMAIL_PASS  // Your Zoho email password or app-specific password
                    }
                });

                // Set up email options
                const mailOptions = {
                    from: process.env.ZOHO_EMAIL_USER, // Sender address
                    to: to, // Recipient address
                    subject: subject, // Subject line
                    html: htmlContent // HTML body
                };

                // Send the email
                await transporter.sendMail(mailOptions);
                console.log('Email sent successfully');
            } catch (error) {
                console.error('Error sending email:', error);
                throw error;
            }
        };

        const emailSubject = 'Your OTP Code for Selar';
        const emailContent = `
            <p>Hello, ${fullName},</p>
            <p>Here is your OTP code: <strong>${otp}</strong>.</p>
            <p>It will expire in 10 minutes.</p>
            <p>Your verification token is: <strong>${token}</strong></p>
        `;

        try {
            await sendEmail(email, emailSubject, emailContent);
            res.json({
  success: true,
  message: 'Signup successful. Check your email to verify your account.',
  token
});
        } catch (error) {
            return res.status(500).json({ message: 'Failed to send OTP. Please try again.' });
        }

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Signup failed. Please try again.' });
    }
});



// Define the sendEmail function
async function sendEmail(to, subject, htmlContent) {
    try {
        const transporter = nodemailer.createTransport({
            host: 'smtp.zoho.com', // Zoho SMTP server
            port: 465, // SSL port
            secure: true, // Use SSL
            auth: {
                user: process.env.ZOHO_EMAIL_USER, // Your Zoho email
                pass: process.env.ZOHO_EMAIL_PASS  // Your Zoho email password or app-specific password
            }
        });

        // Set up email options
        const mailOptions = {
            from: process.env.ZOHO_EMAIL_USER, // Sender address
            to: to, // Recipient address
            subject: subject, // Subject line
            html: htmlContent // HTML body
        };

        // Send the email
        await transporter.sendMail(mailOptions);
        console.log('Email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error);
    }
}





// Simplified OTP verification route
app.post('/api/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    try {
        // Check if the email and OTP match in the database
        const [user] = await db.query('SELECT * FROM users WHERE email = ? AND otp = ?', [email, otp]);

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid OTP. Please try again.' });
        }

        // Mark user as verified
        await db.query('UPDATE users SET verified = ? WHERE email = ?', [true, email]);

        res.json({ success: true, message: 'Email verified successfully! You can now log in.' });
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ success: false, message: 'An error occurred during verification. Please try again.' });
    }
});




app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check for missing email or password
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }

        // Check if the user is admin first
        if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
            console.log('Admin login successful for:', email);
            return res.json({ success: true, message: 'Admin login successful!', userEmail: email, isAdmin: true });
        }

        // Fetch user from the database
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        // Ensure the query returns a user
        if (users.length === 0) {
            console.log('User not found:', email);
            return res.status(400).json({ success: false, message: 'Invalid email or password.' });
        }

        const user = users[0]; // Get the first user object

        // Debugging: Check the fetched user details
        console.log('Fetched user:', user);
        console.log('User password from DB:', user.password);
        console.log('Password from client:', password);

        // Check if the password is present in the database
        if (!user.password) {
            console.log('User password is missing for email:', email);
            return res.status(400).json({ success: false, message: 'User password is missing.' });
        }

        // Directly compare the plain text passwords
        if (password !== user.password) {
            console.log('Password mismatch for user:', email);
            return res.status(400).json({ success: false, message: 'Invalid email or password.' });
        }

        // Successful login for normal user
        console.log('Login successful for user:', email);
        res.json({ success: true, message: 'Login successful!', userEmail: email, isAdmin: false });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'An error occurred during login.' });
    }
});


app.get('/api/news', async (req, res) => {
  const category = req.query.category || 'general';
  const NEWS_API_KEY = '16a42969c1424ceb879197d2e62c760a';
  const url = `https://newsapi.org/v2/top-headlines?country=us&category=${category}&apiKey=${NEWS_API_KEY}`;

  try {
    const response = await fetch(url, {
      headers: { 'Accept': 'application/json' },
    });

    const contentType = response.headers.get('content-type');
    
    if (!contentType || !contentType.includes('application/json')) {
      const rawText = await response.text();
      console.error('Non-JSON response body:', rawText);
      throw new Error('Expected JSON but got something else');
    }

    const data = await response.json();
    console.log('Raw API data:', data);


    if (!data.articles) {
      console.error('API response missing "articles":', data);
      throw new Error('Missing "articles" field in API response');
    }

    // ✅ FIX HERE: send response as { news: [...] }
    const transformed = data.articles.map(article => ({
      title: article.title,
      description: article.description || '',
      imgUrl: article.urlToImage || 'https://via.placeholder.com/400x200?text=No+Image',
      link: article.url,
      feedDate: article.publishedAt
    }));

    console.log('News fetched successfully');
    res.json({ news: transformed }); // ✅ match frontend expectations
    console.log(transformed)
  } catch (error) {
    console.error('Error fetching news:', error.message);
    res.status(500).json({ error: 'Failed to fetch news. See logs for more info.' });
  }
});






// API route to get user balance
app.get('/api/getBalance', async (req, res) => {
    const userEmail = req.query.email;

    if (!userEmail) {
        return res.status(400).json({ error: 'Email is required' });
    }

    try {
        const [results] = await db.query('SELECT balance FROM users WHERE email = ?', [userEmail]);
        
        if (results.length > 0) {
            res.json({ balance: results[0].balance });
        } else {
            res.json({ balance: null }); // User not found
        }
    } catch (error) {
        console.error('Error fetching balance:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});


app.get('/api/user/history', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: "Missing email" });

    console.log("Fetching deposit history for:", email);

    // Adjust this based on your actual DB method
    const history = await db.query(
      'SELECT amount, date FROM deposits WHERE email = ? ORDER BY date ASC',
      [email]
    );

    res.json({ history }); // 👈 match expected frontend format
  } catch (error) {
    console.error("Error fetching user history:", error);
    res.status(500).json({ error: "Server error" });
  }
});



// GET /api/user/transactions
app.get('/api/user/transactions', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'Email required' });

  try {
    const recent = await db.collection('transactions')
      .find({ email }).sort({ date: -1 }).limit(5).toArray();
    
    res.json(recent);
  } catch (err) {
    res.status(500).json({ error: 'DB error fetching transactions' });
  }
});




app.post('/api/create-payment-intent', async (req, res) => {
    const { amount } = req.body; // Get amount from request

    try {
        const paymentIntent = await stripe.paymentIntents.create({
            amount: amount,
            currency: 'usd', // Change this to your desired currency
            // Optional: Add more options here if needed
        });
        res.send({ clientSecret: paymentIntent.client_secret });
    } catch (error) {
        console.error('Error creating payment intent:', error);
        res.status(500).send({ error: 'Failed to create payment intent.' });
    }
});


app.post('/api/create-deposit', async (req, res) => {
    const { email, amount, deposit_method } = req.body; // Ensure deposit_method is used here

    if (!email || !amount || !deposit_method) {
        return res.status(400).json({ message: 'Missing required fields' });
    }

    const investmentStartDate = new Date(); // Current date for investment start
    const investmentEndDate = null; // Set to null for now, will calculate later

    try {
        // Insert into deposits table
        const depositResult = await db.query(
            'INSERT INTO deposits (email, amount, date, status, investment_start_date, investment_end_date, plan_name, deposit_method) VALUES (?, ?, NOW(), ?, ?, ?, ?, ?)',
            [email, amount, 'pending', investmentStartDate, investmentEndDate, null, deposit_method] // Plan name is null
        );

        // Insert into transactions table
        const transactionResult = await db.query(
            'INSERT INTO transactions (email, plan_name, plan_profit, plan_principle_return, plan_credit_amount, plan_deposit_fee, plan_debit_amount, deposit_method, transaction_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())',
            [email, null, null, null, amount, 0, amount, deposit_method] // Nulls for plan details, adjust if necessary
        );

        res.status(201).json({ message: 'Deposit created successfully', depositId: depositResult.insertId });
    } catch (error) {
        console.error('Error creating deposit:', error);
        res.status(500).json({ message: 'Error creating deposit', error });
    }
});



app.post('/api/getBalance', async (req, res) => {
    const { email } = req.body;

    try {
        const [result] = await db.query(
            'SELECT username, password, balance FROM users WHERE email = ?',
            [email]
        );

        if (result.length > 0) {
            const { username, password, balance } = result[0];
            res.json({ success: true, username, balance });
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    } catch (err) {
        console.error('Error fetching user data:', err);
        res.status(500).json({ success: false, message: 'Error fetching user data' });
    }
});




app.post('/api/deposit', async (req, res) => {
    try {
        const { 
            email, 
            depositAmount, 
            planName, 
            planPrincipleReturn, 
            planCreditAmount, 
            planDepositFee, 
            planDebitAmount, 
            depositMethod 
        } = req.body;

        if (!email || !planName || !planCreditAmount || !depositAmount || !depositMethod) {
            return res.status(400).json({ message: "Please provide all required fields" });
        }

        const [userResult] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        const user = userResult[0];

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (depositMethod === 'balance') {
            if (user.balance < depositAmount) {
                return res.status(400).json({ message: 'Insufficient balance' });
            }
            await db.query('UPDATE users SET balance = balance - ? WHERE email = ?', [depositAmount, email]);
        }

        const planEndTimes = {
            '10% RIO AFTER 24 HOURS': 24 * 60 * 60 * 1000,
            '20% RIO AFTER 72 HOURS': 72 * 60 * 60 * 1000,
            '50% RIO LONG TERM': 7 * 24 * 60 * 60 * 1000,
            '100% RIO AFTER 14 DAYS': 14 * 24 * 60 * 60 * 1000
        };

        const investmentStartDate = new Date();
        const investmentEndDate = new Date(investmentStartDate.getTime() + (planEndTimes[planName] || 0));

        await db.query(
            `INSERT INTO transactions 
            (email, plan_name, plan_principle_return, plan_credit_amount, plan_deposit_fee, plan_debit_amount, deposit_method, transaction_date) 
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
            [email, planName, planPrincipleReturn, planCreditAmount, planDepositFee, planDebitAmount, depositMethod]
        );

        await db.query(
            `INSERT INTO deposits 
            (email, amount, date, investment_start_date, investment_end_date, plan_name, plan_principle_return, plan_credit_amount, plan_deposit_fee, plan_debit_amount, deposit_method, status) 
            VALUES ((SELECT email FROM users WHERE email = ?), ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
            [email, depositAmount, investmentStartDate, investmentEndDate, planName, planPrincipleReturn, planCreditAmount, planDepositFee, planDebitAmount, depositMethod]
        );

        // Inline email sending
        const transporter = nodemailer.createTransport({
            host: 'smtp.zoho.com',
            port: 465,
            secure: true,
            auth: {
                user: process.env.ZOHO_EMAIL_USER,
                pass: process.env.ZOHO_EMAIL_PASS
            }
        });

        const emailContent = `
           <p>Dear ${email},</p>
    <p>Your deposit of <strong>$${depositAmount}</strong> has been successfully submitted.</p>
    <p>It will reflect in your "Active Deposits" once confirmed by the admin after verification.</p>
    <p>Thank you for choosing Biggy Capital.</p>
    <p><a href="https://www.biggycapital.online/">Return to Dashboard</a></p>
    <hr />
    <small>&copy; 2025 Biggy Capital. All rights reserved.</small>
        `;

        await transporter.sendMail({
            from: process.env.ZOHO_EMAIL_USER,
            to: user.email,
            subject: 'Deposit Confirmation',
            html: emailContent
        });

        console.log('Email sent successfully.');

        res.json({ success: true, message: 'Deposit successful. Confirmation email sent.' });

    } catch (err) {
        console.error('Error processing deposit:', err);
        res.status(500).json({ message: 'Error processing deposit' });
    }
});



// Cron job to check for completed investments and update balances
const checkInvestmentEnd = async () => {
    try {
        const now = new Date();

        // Retrieve active deposits where the investment end date has passed
        const [activeDeposits] = await db.query(
            `SELECT id, email, amount, profit, plan_name, investment_start_date, investment_end_date 
             FROM active_deposits 
             WHERE investment_end_date <= ?`,
            [now]
        );

        for (const deposit of activeDeposits) {
            const { amount, profit, email, plan_name, investment_start_date, investment_end_date, id } = deposit;

            // Calculate the interest based on the profit percentage
            const interestAmount = amount * (profit / 100);
            console.log(`Interest calculated for deposit ${id}: ${interestAmount}`);

            // Get the user's current balance from the database using their email
            const [userBalance] = await db.query(
                `SELECT balance FROM users WHERE email = ?`,
                [email]
            );

            // Check if userBalance is empty
            if (userBalance.length === 0) {
                console.error(`User with email ${email} not found.`);
                continue; // Skip this deposit and continue with the next one
            }

            // Convert amount to a number (if it's a string) to ensure correct mathematical operations
            const amountAsNumber = parseFloat(amount); // Convert string to number if needed
            const oldBalance = parseFloat(userBalance[0].balance); // Ensure old balance is a number

            // Calculate the new balance (capital + interest)
            const newBalance = oldBalance + amountAsNumber + interestAmount;

            // Round the balance to two decimal places
            const roundedNewBalance = Math.round(newBalance * 100) / 100;
            const formattedNewBalance = roundedNewBalance.toFixed(2); // Ensure two decimal places

            console.log(`Calculated New Balance (unrounded): ${newBalance}`);
            console.log(`Rounded New Balance: ${roundedNewBalance}`);
            console.log(`Formatted New Balance: ${formattedNewBalance}`);

            // Log before updating the database
            console.log(`Updating balance for user ${email}: Old Balance = ${oldBalance}, New Balance = ${formattedNewBalance}`);

            // Update the user's balance with the new amount (capital + interest)
            await db.query(
                `UPDATE users 
                 SET balance = ? 
                 WHERE email = ?`,
                [formattedNewBalance, email]
            );

            // Move record to completed_deposits table
            await db.query(
                `INSERT INTO completed_deposits (email, amount, interest, plan_name, investment_start_date, investment_end_date, date_completed)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [email, amountAsNumber, interestAmount, plan_name, investment_start_date, investment_end_date, now]
            );

            // Remove deposit from active_deposits
            await db.query(
                `DELETE FROM active_deposits 
                 WHERE id = ?`,
                [id]
            );
            console.log(`Deposit ${id} moved to completed_deposits and removed from active_deposits.`);
        }

        console.log('Investment end check completed, including interest addition.');
    } catch (err) {
        console.error('Error checking investments:', err);
    }
};

// Schedule the cron job to run every 2 minutes
cron.schedule('*/2 * * * *', () => {
    console.log('Running scheduled task to check completed investments.');
    checkInvestmentEnd();
});


// Route to fetch bitcoin_address and balance on page load
app.get('/api/user-info', (req, res) => {
    const { username } = req.query; // Username will be sent from the frontend
  
    db.query( // Change pool to db
        'SELECT bitcoin_address, balance FROM users WHERE username = ?',
        [username],
        (error, results) => {
            if (error) {
                console.error('Error fetching user info:', error);
                return res.status(500).json({ message: 'Error fetching user info.' });
            }
            if (results.length === 0) {
                return res.status(404).json({ message: 'User not found.' });
            }
            const userInfo = results[0];
            res.json(userInfo); // Send the bitcoin_address and balance
        }
    );
});


// Route to fetch deposits and withdrawals
app.get('/api/transactions', async (req, res) => {
    const { email } = req.query; // Email will be sent from the frontend

    try {
        const [withdrawals] = await db.query(
            'SELECT amount, request_date, status FROM pending_withdrawals WHERE email = ?',
            [email]
        );

        const [deposits] = await db.query(
            'SELECT amount, deposit_method, date, status FROM deposits WHERE email = ?',
            [email]
        );

        res.json({ withdrawals, deposits });
    } catch (error) {
        console.error('Error fetching transactions:', error);
        res.status(500).json({ message: 'Error fetching transactions.' });
    }
});





// Route for handling withdrawal
app.post('/api/withdraw', async (req, res) => {
    console.log('Withdrawal endpoint hit'); // Confirms endpoint is accessed

    const { userEmail, amount, method, walletAddress, bankDetails } = req.body;
    console.log("Received withdrawal request with data:", req.body); // Logs request data for debugging

    if (!db) {
        console.error('Database connection (db) is not defined.');
        return res.status(500).json({ message: 'Database connection error.' });
    }

    // Prepare SQL and parameters based on withdrawal method
    let query = '';
    let queryParams = [];
    if (method === 'bank') {
        const { bankName, accountName, accountNumber } = bankDetails;
        query = 'INSERT INTO pending_withdrawals (email, amount, status, request_date, bank_name, account_name, account_number, method) VALUES (?, ?, ?, NOW(), ?, ?, ?, ?)';
        queryParams = [userEmail, amount, 'pending', bankName, accountName, accountNumber, method];
        console.log("Bank withdrawal for user:", userEmail);
    } else if (method === 'wallet') {
        query = 'INSERT INTO pending_withdrawals (email, amount, status, request_date, wallet_address, method) VALUES (?, ?, ?, NOW(), ?, ?)';
        queryParams = [userEmail, amount, 'pending', walletAddress, method];
        console.log("Wallet withdrawal for user:", userEmail);
    } else {
        console.log("Invalid withdrawal method.");
        return res.status(400).json({ message: 'Invalid withdrawal method selected.' });
    }

    try {
        // Log the withdrawal request in the database
        console.log("Inserting withdrawal request into database with query:", query);
        const [result] = await db.query(query, queryParams);
        
        if (result.affectedRows === 0) {
            console.log("No rows inserted for the withdrawal request.");
            return res.status(500).json({ message: 'Failed to insert withdrawal request.' });
        }

        console.log('Withdrawal request logged successfully, ID:', result.insertId);

        // Deduct the withdrawal amount from the user's balance
        const balanceUpdateQuery = 'UPDATE users SET balance = balance - ? WHERE email = ?';
        const balanceParams = [amount, userEmail];
        console.log("Updating user balance with query:", balanceUpdateQuery);
        
        const [balanceUpdateResult] = await db.query(balanceUpdateQuery, balanceParams);

        if (balanceUpdateResult.affectedRows === 0) {
            console.log("Balance deduction failed, no rows updated.");
            return res.status(500).json({ message: 'Failed to deduct balance.' });
        }

        console.log("User balance updated successfully.");

        // Send a notification email to the user
        const emailSubject = "Withdrawal Request Received";
        const emailBody = `
         <div style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4;">
                <table width="100%" style="max-width: 600px; margin: auto; border-collapse: collapse;">
                    <tr>
                        <td style="text-align: center; padding: 20px;">
                            <img src="https://srexxy.onrender.com/images/selar%20logo.png" alt="Company Logo" style="max-width: 30%; height: auto;" />
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color:rgb(220, 42, 255); padding: 20px; text-align: center; color: white;">
                            <h1 style="margin: 0;">Withdrawal Successful!</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: white; padding: 20px;">
                           <p>Your withdrawal request of ${amount} has been received and is pending approval.</p>
                            <p style="font-size: 16px; line-height: 1.5;">Thank you for investing with us!</p>
                            <a href="https://www.biggycapital.online/" style="display: inline-block; background-color:rgb(255, 255, 255); color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px;">Return to Dashboard</a>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: #f4f4f4; padding: 10px; text-align: center;">
                            <p style="font-size: 12px; color:rgb(237, 42, 255);">&copy; 2025 Selar. All rights reserved.</p>
                        </td>
                    </tr>
                </table>
            </div>
        
        `;
        await sendEmail(userEmail, emailSubject, emailBody);
        console.log("Notification email sent to user:", userEmail);

        res.json({ message: 'Withdrawal request submitted successfully.' });
    } catch (error) {
        console.error('Error processing withdrawal request:', error); // Logs error for further inspection
        res.status(500).json({ message: 'Error processing withdrawal request.' });
    }
});



// Global error handlers for unhandled errors
process.on('uncaughtException', (err) => {
    console.error('Unhandled exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled rejection at:', promise, 'reason:', reason);
});




app.post('/api/assets', async (req, res) => {
    try {
        const { email } = req.body; // Extract email from the request body
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }
        
        // Fetch active deposits for the user
        const [deposits] = await db.query('SELECT * FROM active_deposits WHERE email = ?', [email]);
        
        // Fetch transactions for the user
        const [transactions] = await db.query('SELECT * FROM transactions WHERE email = ?', [email]);
        console.log('Deposits:', deposits);

        // Calculate total amount of active deposits
        const totalAmount = deposits.length > 0
        ? deposits.reduce((acc, deposit) => acc + parseFloat(deposit.amount), 0)
        : 0;
        console.log('Calculated Total Amount (Fixed):', totalAmount);


        // Ensure totalAmount is a number
        res.json({ totalAmount: Number(totalAmount), deposits, transactions }); // Send the data as JSON response
    } catch (error) {
        console.error('Error fetching assets:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



app.get('/get-user-profile', async (req, res) => {
    console.log(req.query);  // Add this to debug
    const email = req.query.email;
    try {
        const [rows] = await db.execute('SELECT fullName, phone, address, email, profile_image FROM users WHERE email = ?', [email]);
        if (rows.length > 0) {
            res.json({ success: true, ...rows[0] });
        } else {
            res.json({ success: false, message: "User not found." });
        }
    } catch (err) {
        console.error('Error:', err);  // Log the error to debug
        res.json({ success: false, message: "Error fetching profile." });
    }
});


app.post('/update-profile', async (req, res) => {
    const { fullName, phone, address, current_password, new_password, confirm_password, email } = req.body;

    try {
        // Validate current password if user tries to change it
        if (current_password && new_password && confirm_password) {
            const [user] = await db.execute('SELECT password FROM users WHERE email = ?', [email]);
            if (!bcrypt.compareSync(current_password, user[0].password)) {
                return res.json({ success: false, message: "Incorrect current password." });
            }
            if (new_password !== confirm_password) {
                return res.json({ success: false, message: "New passwords do not match." });
            }
            const hashedPassword = bcrypt.hashSync(new_password, 10);
            await db.execute('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
        }

        // Update other fields
        await db.execute('UPDATE users SET fullName = ?, phone = ?, address = ? WHERE email = ?', [fullName, phone, address, email]);
        res.json({ success: true, message: "Profile updated successfully." });
    } catch (err) {
        res.json({ success: false, message: "Error updating profile." });
    }
});

app.post('/update-profile-picture', async (req, res) => {
    const { email } = req.body;
    const profileImage = req.files.profile_image;

    try {
        // Save profile image to disk and store its path in the database
        const imagePath = `/uploads/${profileImage.name}`;
        profileImage.mv(`./public/uploads/${profileImage.name}`);
        await db.execute('UPDATE users SET profile_image = ? WHERE email = ?', [imagePath, email]);

        res.json({ success: true, message: "Profile picture updated.", profile_image_url: imagePath });
    } catch (err) {
        res.json({ success: false, message: "Error updating profile picture." });
    }
});



app.get('/api/stocks', (req, res) => {
    const options = {
        method: 'GET',
        hostname: 'yahoo-finance-api-data.p.rapidapi.com',
        port: null,
        path: '/search/list-detail?id=a4f8a58b-e458-44fe-b304-04af382a364e&limit=10&offset=0',
        headers: {
            'x-rapidapi-key': '665e2072eemsh27d4020afed09f6p1e7c0fjsn1c3c3bfeedde', // Replace with your key
            'x-rapidapi-host': 'yahoo-finance-api-data.p.rapidapi.com'
        }
    };

    // Use a different variable name to avoid conflicts
    const stockRequest = https.request(options, (apiRes) => {
        let chunks = [];

        apiRes.on('data', (chunk) => {
            chunks.push(chunk);
        });

        apiRes.on('end', () => {
            const body = Buffer.concat(chunks);
            const result = JSON.parse(body.toString());
            res.json(result); // Send data to the front-end
        });
    });

    stockRequest.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
        res.status(500).send('Error fetching stock data');
    });

    stockRequest.end();
});

// Route to create a Flutterwave payment link
router.post('/create-payment-link', async (req, res) => {
    const { email, amount, planDetails, depositMethod } = req.body;

    try {
        // Flutterwave API request to create a payment link
        const response = await axios.post(
            'https://api.flutterwave.com/v3/payments',
            {
                tx_ref: `tx_${Date.now()}`, // Unique transaction reference
                amount,
                currency: 'USD', // Adjust this to your desired currency
                redirect_url: 'https://moniegram.onrender.com/main-page.html', // Update with your callback URL
                customer: {
                    email,
                },
                meta: {
                    email,
                    plan_name: planDetails.plan_name,
                    deposit_method: depositMethod,
                },
                customizations: {
                    title: 'Deposit Payment',
                    description: `Payment for ${planDetails.plan_name}`,
                },
            },
            {
                headers: {
                    Authorization: `Bearer ${process.env.FLUTTERWAVE_SECRET_KEY}`,
                },
            }
        );

        const paymentLink = response.data.data.link;
        res.status(200).send({ paymentLink });
    } catch (error) {
        console.error('Error creating Flutterwave payment link:', error.response?.data || error.message);
        res.status(500).send('Error creating payment link');
    }
});

// Flutterwave webhook to handle payment confirmation
router.post('/webhook', async (req, res) => {
    const secretHash = process.env.FLUTTERWAVE_WEBHOOK_SECRET;

    // Validate the webhook signature
    const signature = req.headers['verif-hash'];
    if (!signature || signature !== secretHash) {
        return res.status(401).send('Unauthorized');
    }

    const payload = req.body;

    // Handle successful payment
    if (payload.event === 'charge.completed' && payload.data.status === 'successful') {
        const paymentData = payload.data;

        // Extract necessary data
        const email = paymentData.customer.email;
        const amount = paymentData.amount;
        const planName = paymentData.meta.plan_name;
        const depositMethod = paymentData.meta.deposit_method;

        // Plan details (adjust as needed)
        const planDetails = {
            plan_name: planName,
            plan_principle_return: 1000, // Example value
            plan_credit_amount: 1200, // Example value
            plan_deposit_fee: 50, // Example value
            plan_debit_amount: 1150, // Example value
        };

        const transactionDate = new Date();
        const investmentStartDate = new Date(); // Modify as needed
        const investmentEndDate = new Date();
        investmentEndDate.setMonth(investmentEndDate.getMonth() + 1); // Example: 1-month duration

        try {
            // Insert into deposits table
            await db.execute(
                `INSERT INTO deposits (email, amount, date, status, investment_start_date, investment_end_date, 
                plan_name, plan_principle_return, plan_credit_amount, plan_deposit_fee, plan_debit_amount, deposit_method) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    email,
                    amount,
                    transactionDate,
                    'completed', // Status of the deposit
                    investmentStartDate,
                    investmentEndDate,
                    planDetails.plan_name,
                    planDetails.plan_principle_return,
                    planDetails.plan_credit_amount,
                    planDetails.plan_deposit_fee,
                    planDetails.plan_debit_amount,
                    depositMethod,
                ]
            );

            // Insert into transactions table
            await db.execute(
                `INSERT INTO transactions (email, plan_name, plan_profit, plan_principle_return, plan_credit_amount, 
                plan_deposit_fee, plan_debit_amount, deposit_method, transaction_dateand) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    email,
                    planDetails.plan_name,
                    planDetails.plan_credit_amount - planDetails.plan_principle_return, // Profit calculation
                    planDetails.plan_principle_return,
                    planDetails.plan_credit_amount,
                    planDetails.plan_deposit_fee,
                    planDetails.plan_debit_amount,
                    depositMethod,
                    transactionDate,
                ]
            );

            res.status(200).send('Payment processed and recorded successfully.');
        } catch (dbError) {
            console.error('Database error:', dbError);
            res.status(500).send('Failed to record payment.');
        }
    } else {
        res.status(400).send('Unhandled event');
    }
});




// app.post('/verify-payment', async (req, res) => {
//     const { reference, amount } = req.body;
//     const paystackSecretKey = 'sk_live_9531183b8354a342dbe10d01e3abee48e6d9f07e';  // replace with your live secret key
  
//     try {
//       const response = await axios.get(`https://api.paystack.co/transaction/verify/${reference}`, {
//         headers: {
//           Authorization: `Bearer ${paystackSecretKey}`
//         }
//       });
  
//       const paymentData = response.data.data;
  
//       if (paymentData && paymentData.status === 'success' && paymentData.amount / 100 === amount && paymentData.currency === 'USD') {
//         // Successful payment in USD
//         return res.json({ success: true, message: 'Payment verified successfully.' });
//       } else {
//         return res.json({ success: false, message: 'Payment verification failed.' });
//       }
//     } catch (error) {
//       console.error(error);
//       res.status(500).json({ success: false, message: 'Server error during payment verification.' });
//     }
//   });
  







//admin


// Route to get the count of pending deposits
app.get('/api/admin/pending-deposits', async (req, res) => {
    try {
        const [deposits] = await db.query(
            `SELECT id, email, amount, plan_name, status, date 
             FROM deposits 
             WHERE status = 'pending'`
        );
        res.json(deposits); // Send the deposits list to the frontend
    } catch (error) {
        console.error('Error fetching pending deposits:', error);
        res.status(500).json({ message: 'Error fetching pending deposits' });
    }
});


// Approve a deposit
router.post('/api/admin/pending-deposits/approve/:id', async (req, res) => {
    const depositId = req.params.id;

    try {
        // Fetch deposit details
        const [depositResult] = await db.query('SELECT * FROM deposits WHERE id = ?', [depositId]);
        if (!depositResult.length) {
            return res.status(404).json({ message: 'Deposit not found' });
        }

        const { email, amount, plan_name, investment_start_date } = depositResult[0];

        // If plan_name exists, fetch the plan details; otherwise, set default values
        let planDetails = {};
        let interest = 0;
        let startDate = new Date();
        let endDate = new Date();
        if (plan_name) {
            // Fetch plan details
            const [planResult] = await db.query('SELECT duration, profit FROM plans WHERE name = ?', [plan_name]);
            if (planResult.length) {
                const { duration, profit } = planResult[0];
                planDetails = { plan_name, profit };
                interest = amount * (profit / 100);
                startDate = new Date(investment_start_date);
                endDate = new Date(startDate.getTime() + duration * 60 * 60 * 1000);
            } else {
                return res.status(404).json({ message: 'Plan not found' });
            }
        } else {
            // For wallet deposits, set default values
            planDetails = { plan_name: 'Wallet Deposit', profit: 0 };
            interest = 0; // No interest for wallet deposit
            startDate = new Date();
            endDate = new Date();
        }

        // Update deposit status
        await db.query('UPDATE deposits SET status = ? WHERE id = ?', ['approved', depositId]);

        // Insert into active deposits
        await db.query(
            `INSERT INTO active_deposits (email, amount, interest, plan_name, profit, investment_start_date, investment_end_date) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [email, amount, interest, planDetails.plan_name, planDetails.profit, startDate, endDate]
        );

        res.json({ message: 'Deposit approved and moved to active deposits successfully' });
    } catch (error) {
        console.error('Error approving deposit:', error);
        res.status(500).json({ message: 'Error approving deposit' });
    }
});





// Reject a deposit
app.post('/api/admin/reject-deposit', async (req, res) => {
    const { depositId } = req.body;

    try {
        // Step 1: Check if deposit exists
        const [depositResult] = await db.query('SELECT * FROM deposits WHERE id = ?', [depositId]);
        if (!depositResult.length) {
            return res.status(404).json({ message: 'Deposit not found' });
        }

        // Step 2: Move deposit to rejected_deposits
        await db.query(
            `INSERT INTO rejected_deposits 
             (id, email, amount, status, date) 
             SELECT id, email, amount, status, date FROM deposits WHERE id = ?`,
            [depositId]
        );

        // Step 3: Delete deposit from deposits table
        await db.query('DELETE FROM deposits WHERE id = ?', [depositId]);

        res.json({ message: 'Deposit rejected successfully' });
    } catch (error) {
        console.error('Error rejecting deposit:', error);
        res.status(500).json({ message: 'Error rejecting deposit' });
    }
});




app.get('/api/pending-withdrawals', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM pending_withdrawals WHERE status = ?', ['Pending']);
        res.status(200).json(results);
    } catch (error) {
        console.error('Error fetching pending withdrawals:', error);
        res.status(500).json({ error: 'Failed to fetch pending withdrawals' });
    }
});



// Approve Withdrawal
app.post('/api/withdrawals/approve', async (req, res) => {
    const { id } = req.body;

    try {
        // Fetch withdrawal details
        const [withdrawal] = await db.query('SELECT email, amount FROM pending_withdrawals WHERE id = ?', [id]);

        if (withdrawal.length === 0) {
            return res.status(404).json({ message: 'Withdrawal not found' });
        }

        const { email, amount } = withdrawal[0];

        // Update withdrawal status
        const [result] = await db.query(
            'UPDATE pending_withdrawals SET status = ?, approved_date = NOW() WHERE id = ?',
            ['Approved', id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Withdrawal not found' });
        }

        // Send approval email
        const emailContent = `
            <div style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4;">
                <table width="100%" style="max-width: 600px; margin: auto; border-collapse: collapse;">
                    <tr>
                        <td style="text-align: center; padding: 20px;">
                            <img src="https://srexxy.onrender.com/images/selar%20logo.png" alt="Company Logo" style="max-width: 30%; height: auto;" />
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color:rgb(237, 42, 255); padding: 20px; text-align: center; color: white;">
                            <h1 style="margin: 0;">Withdrawal Approved!</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: white; padding: 20px;">
                            <p style="font-size: 16px; line-height: 1.5;">Dear ${email},</p>
                            <p style="font-size: 16px; line-height: 1.5;">Your withdrawal request of $${amount} has been successfully approved. The funds will be transferred shortly.</p>
                            <p style="font-size: 16px; line-height: 1.5;">Thank you for choosing Biggy Capitals!</p>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: #f4f4f4; padding: 10px; text-align: center;">
                            <p style="font-size: 12px; color:rgb(230, 42, 255);">&copy; Biggycapitals @2025. All rights reserved.</p>
                        </td>
                    </tr>
                </table>
            </div>
        `;

        await sendEmail(email, 'Withdrawal Approved', emailContent);

        res.status(200).json({ message: 'Withdrawal approved successfully and email sent' });
    } catch (error) {
        console.error('Error approving withdrawal:', error);
        res.status(500).json({ message: 'Error approving withdrawal' });
    }
});



// Reject Withdrawal and Refund User
app.post('/api/withdrawals/reject', async (req, res) => {
    const { id } = req.body;

    try {
        // Start a transaction
        await db.query('START TRANSACTION');

        // Fetch withdrawal details
        const [withdrawal] = await db.query('SELECT email, amount FROM pending_withdrawals WHERE id = ?', [id]);

        if (withdrawal.length === 0) {
            return res.status(404).json({ message: 'Withdrawal not found' });
        }

        const { email, amount } = withdrawal[0];

        // Update withdrawal status to Rejected
        const [updateWithdrawal] = await db.query(
            'UPDATE pending_withdrawals SET status = ? WHERE id = ?',
            ['Rejected', id]
        );

        if (updateWithdrawal.affectedRows === 0) {
            throw new Error('Failed to update withdrawal status');
        }

        // Refund the amount to the user's balance
        const [updateBalance] = await db.query(
            'UPDATE users SET balance = balance + ? WHERE email = ?',
            [amount, email]
        );

        if (updateBalance.affectedRows === 0) {
            throw new Error('Failed to update user balance');
        }

        // Commit the transaction
        await db.query('COMMIT');

        // Send rejection email
        const emailContent = `
            <div style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4;">
                <table width="100%" style="max-width: 600px; margin: auto; border-collapse: collapse;">
                    <tr>
                        <td style="text-align: center; padding: 20px;">
                            <img src="https://srexxy.onrender.com/images/selar%20logo.png" alt="Company Logo" style="max-width: 30%; height: auto;" />
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color:rgb(255, 51, 51); padding: 20px; text-align: center; color: white;">
                            <h1 style="margin: 0;">Withdrawal Rejected!</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: white; padding: 20px;">
                            <p style="font-size: 16px; line-height: 1.5;">Dear ${email},</p>
                            <p style="font-size: 16px; line-height: 1.5;">Your withdrawal request of $${amount} has been rejected. The amount has been refunded to your account balance.</p>
                            <p style="font-size: 16px; line-height: 1.5;">If you have any questions, feel free to contact support.</p>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: #f4f4f4; padding: 10px; text-align: center;">
                            <p style="font-size: 12px; color:rgb(248, 51, 255);">&copy; Biggycapitals @2025.. All rights reserved.</p>
                        </td>
                    </tr>
                </table>
            </div>
        `;

        await sendEmail(email, 'Withdrawal Rejected', emailContent);

        res.status(200).json({ message: 'Withdrawal rejected, amount refunded, and email sent' });
    } catch (error) {
        // Rollback transaction on error
        await db.query('ROLLBACK');
        console.error('Error rejecting withdrawal:', error);
        res.status(500).json({ message: 'Error rejecting withdrawal and refunding amount' });
    }
});





app.get('/api/admin/user-details', async (req, res) => {
    try {
        const { email } = req.query;

        if (!email) {
            return res.status(400).json({ message: 'Email parameter is required' });
        }

        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = rows[0]; 
        res.json({
            id: user.id,
            full_name: user.full_name,
            email: user.email,
            username: user.username,
            bitcoin_address: user.bitcoin_address,
            referral_code: user.referral_code,
            created_at: user.created_at,
            balance: user.balance,
            total_withdrawals: user.total_withdrawals,
            total_deposits: user.total_deposits
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});



app.post('/api/admin/add-funds', async (req, res) => {
    const { email, amount, description, actionType, authPassword, planId } = req.body;

    if (!email || !amount || !description || !actionType || !authPassword) {
        return res.status(400).json({ message: 'Missing required fields' });
    }

    try {
        // Validate the admin password
        const adminPassword = process.env.ADMIN_PASSWORD;
        if (authPassword !== adminPassword) {
            return res.status(403).json({ message: 'Invalid admin password' });
        }

        // Fetch user details using email
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        const user = rows[0];

        // Process the action (bonus or investment)
        if (actionType === 'bonus') {
            // Add bonus to user balance
            await db.execute('UPDATE users SET balance = balance + ? WHERE email = ?', [amount, email]);
            
            // Insert transaction log for the bonus
            await db.execute(
                'INSERT INTO transactions (email, plan_name, plan_credit_amount, deposit_method, transaction_date) VALUES (?, ?, ?, ?, ?)',
                [email, null, amount, 'Bonus', new Date()]
            );

            res.json({ message: `Added ${amount} as bonus to ${user.email}` });

        } else if (actionType === 'investment') {
            if (!planId) {
                return res.status(400).json({ message: 'Plan ID is required for investment' });
            }

            // Fetch investment plan details
            let planDetails;
            try {
                planDetails = getPlanDetails(planId);
            } catch (planError) {
                console.error(planError);
                return res.status(404).json({ message: 'Investment plan not found' });
            }

            const { name: plan_name, duration } = planDetails; // duration is in hours

            // Calculate start_date and end_date
            const startDate = new Date(); // Current server time
            const endDate = new Date(startDate.getTime() + duration * 60 * 60 * 1000); // Add duration in hours

            // Insert investment record into active_deposits
            await db.execute(
                `INSERT INTO active_deposits (email, plan_name, amount, investment_start_date, investment_end_date) 
                 VALUES (?, ?, ?, ?, ?)`,
                [email, plan_name, amount, startDate, endDate]
            );

            // Insert transaction log for the investment
            await db.execute(
                `INSERT INTO transactions (email, plan_name, plan_credit_amount, deposit_method, transaction_date) 
                 VALUES (?, ?, ?, ?, ?)`,
                [email, plan_name, amount, 'Investment', startDate]
            );

            res.json({ message: `Added ${amount} as investment to ${user.full_name}` });

        } else {
            res.status(400).json({ message: 'Invalid action type' });
        }

    } catch (error) {
        console.error('Error adding funds:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Helper function to get investment plan details
function getPlanDetails(planId) {
    const plans = {
        1: { name: '10-RIO-AFTER-24-HOURS', duration: 24 },
        2: { name: '20-RIO-AFTER-72-HOURS', duration: 72 },
        3: { name: '50% RIO AFTER 1 WEEK', duration: 168 },
        4: { name: '100-RIO-AFTER-14-DAYS', duration: 336 }
    };
    return plans[planId] || { name: 'Unknown Plan', duration: 0 };
}




app.post('/api/admin/add-penalty', async (req, res) => {
    const { email, penaltyAmount, penaltyType, description, authPassword } = req.body;

    if (!email || !penaltyAmount || !penaltyType || !description || !authPassword) {
        return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    try {
        // Validate the admin password
        const adminPassword = process.env.ADMIN_PASSWORD;
        if (authPassword !== adminPassword) {
            return res.status(403).json({ success: false, message: 'Invalid admin password' });
        }

        // Fetch user details using email
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        const user = rows[0];
        const newBalance = user.balance - parseFloat(penaltyAmount);

        // Update user's balance
        await db.execute('UPDATE users SET balance = ? WHERE email = ?', [newBalance, email]);

        // // Insert penalty log
        // await db.execute(
        //     'INSERT INTO penalties (email, amount, type, description, date) VALUES (?, ?, ?, ?, ?)',
        //     [email, penaltyAmount, penaltyType, description, new Date()]
        // );

        res.json({ success: true, message: `Penalty of ${penaltyAmount} added to ${user.full_name}` });

    } catch (error) {
        console.error('Error adding penalty:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});






  

// Route to get all users' details
app.get('/api/admin/users', async (req, res) => {
    try {
        const query = `
            SELECT id, fullName, email, username, bitcoin_address, referrer, createdAt, updatedAt, otp, verified, phone, address, profile_image, balance
            FROM users
        `;
        // Use db pool to execute the query
        const [results] = await db.query(query);
        res.json(results); // Send the results back as JSON
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ message: 'Error fetching user details.' });
    }
});



app.get('/api/admin/transactions', async (req, res) => {
    const query = `
        SELECT id, email, plan_name, plan_profit, plan_principle_return, 
               plan_credit_amount, plan_deposit_fee, plan_debit_amount, 
               deposit_method, transaction_date
        FROM transactions
    `;

    try {
        const [results] = await db.query(query);  // Using promise-based query here
        res.json(results);  // Send results as JSON
    } catch (error) {
        console.error('Error fetching transactions:', error);
        res.status(500).json({ message: 'Error fetching transactions' });
    }
});



app.get('/api/admin/deposits', async (req, res) => {
    try {
        console.log('Fetching all deposits...');
        const query = `
            SELECT id, email, amount, date, status, investment_start_date, investment_end_date,
                   plan_name, plan_principle_return, plan_credit_amount, plan_deposit_fee, plan_debit_amount, deposit_method
            FROM deposits
        `;

        // Execute the query to fetch all deposits
        const [results] = await db.query(query);
        console.log('Results:', results);

        // Send the results as a JSON response
        res.json(results);
    } catch (error) {
        console.error('Error fetching deposits:', error);
        res.status(500).json({ message: 'Error fetching deposits' });
    }
});



app.get('/api/admin/withdrawals', async (req, res) => {
    try {
        console.log('Fetching all withdrawals...');
        const query = `
            SELECT id, email, amount, status, request_date, approved_date, wallet_address, method,
                   bank_name, account_name, account_number
            FROM pending_withdrawals
        `;

        // Execute the query to fetch all withdrawals
        const [results] = await db.query(query);
        console.log('Results:', results);

        // Send the results as a JSON response
        res.json(results);
    } catch (error) {
        console.error('Error fetching withdrawals:', error);
        res.status(500).json({ message: 'Error fetching withdrawals' });
    }
});



// Handle the newsletter send request
app.post('/api/admin/send-newsletter', async (req, res) => {
    const { subject, content, targetGroups, specificEmail } = req.body;

    try {
        const users = [];
        let query = '';

        // If specificEmail is provided, prioritize that
        if (specificEmail) {
            users.push(specificEmail);
        } else {
            for (const group of targetGroups) {
                if (group === 'allUsers') {
                    query = 'SELECT email FROM users'; // Fetch all users' emails
                } else if (group === 'noInvestments') {
                    query = `SELECT email FROM users WHERE id NOT IN 
                             (SELECT user_id FROM investments)`; // Users with no investments
                } else if (group === 'zeroBalance') {
                    query = 'SELECT email FROM users WHERE balance = 0'; // Users with zero balance
                } else if (group === 'activeInvestments') {
                    query = `
            SELECT u.email 
            FROM users u
            JOIN active_deposits ad ON u.email = ad.email
            WHERE ad.investment_end_date > NOW()`; // Active investments
                } else if (group.startsWith('specificPlan:')) {
                    const planName = group.split(':')[1];
                    query = `
                        SELECT u.email 
                        FROM users u
                        JOIN active_deposits ad ON u.email = ad.email
                        WHERE ad.plan_name = ?`;
                    const [result] = await db.query(query, [planName]);
                    users.push(...result.map(user => user.email));
                    continue;
                }

                const [result] = await db.query(query);
                users.push(...result.map(user => user.email));
            }
        }

        // Remove duplicate emails
        const uniqueEmails = [...new Set(users)];

        // Send email to each user
        for (const email of uniqueEmails) {
            await sendEmail(email, subject, content);
        }

        res.status(200).json({ message: 'Newsletter sent successfully' });
    } catch (error) {
        console.error('Error sending newsletter:', error);
        res.status(500).json({ message: 'Failed to send the newsletter' });
    }
});



// Handle the newsletter send request
// app.post('/api/admin/send-newsletter', async (req, res) => {
//     const { subject, content, targetGroups } = req.body;

//     try {
//         const users = [];
//         let query = '';

//         for (const group of targetGroups) {
//             if (group === 'allUsers') {
//                 query = 'SELECT email FROM users'; // Fetch all users' emails
//             } else if (group === 'noInvestments') {
//                 query = `SELECT email FROM users WHERE id NOT IN 
//                          (SELECT user_id FROM investments)`; // Users with no investments
//             } else if (group === 'zeroBalance') {
//                 query = 'SELECT email FROM users WHERE balance = 0'; // Users with zero balance
//             } else if (group === 'activeInvestments') {
//                 // Fetch users with active deposits from the active_deposits table
//                 query = `
//         SELECT u.email 
//         FROM users u
//         JOIN active_deposits ad ON u.email = ad.email
//         WHERE ad.investment_end_date > NOW()`; // Active investments (from active_deposits table)
//             } else if (group.startsWith('specificPlan:')) {
//                 const planName = group.split(':')[1];
//                 query = `
//                     SELECT u.email 
//                     FROM users u
//                     JOIN active_deposits ad ON u.email = ad.email
//                     WHERE ad.plan_name = ?`;
//                 const [result] = await db.query(query, [planName]);
//                 users.push(...result.map(user => user.email));
//                 continue;
//             }
            

//             const [result] = await db.query(query);
//             users.push(...result.map(user => user.email));
//         }

//         // Remove duplicate emails
//         const uniqueEmails = [...new Set(users)];

//         // Send email to each user
//         for (const email of uniqueEmails) {
//             await sendEmail(email, subject, content);
//         }

//         res.status(200).json({ message: 'Newsletter sent successfully' });
//     } catch (error) {
//         console.error('Error sending newsletter:', error);
//         res.status(500).json({ message: 'Failed to send the newsletter' });
//     }
// });



  // Adjusted route
app.get('/api/expiring-deposits', async (req, res) => {
    try {
        const [deposits] = await db.query(`
            SELECT *, DATEDIFF(investment_end_date, NOW()) AS days_left
            FROM active_deposits
            WHERE investment_end_date > NOW()
        `);
        res.json(deposits);
    } catch (err) {
        console.error('Error fetching expiring deposits:', err);
        res.status(500).json({ message: 'Error fetching expiring deposits' });
    }
});

  




//   app.get('/get-account-details', (req, res) => {
//     const username = req.query.username;
  
//     if (!username) {
//         return res.json({ success: false, message: "Username is required." });
//     }
  
//     // Get a connection from the pool
//     pool.getConnection((err, connection) => {
//         if (err) {
//             return res.json({ success: false, message: "Error connecting to the database." });
//         }
  
//         // Query user data based on the username to get user_id
//         const userQuery = `SELECT id, full_name, username, created_at, balance FROM users WHERE username = ?`;
//         connection.query(userQuery, [username], (err, userResults) => {
//             if (err) {
//                 connection.release(); // Release connection back to the pool
//                 return res.json({ success: false, message: "Error fetching user data." });
//             }
  
//             if (userResults.length === 0) {
//                 connection.release(); // Release connection back to the pool
//                 return res.json({ success: false, message: "User not found." });
//             }
  
//             const user = userResults[0];
//             const userId = user.id;
  
//             // Query approved deposits using user_id
//             const approvedDepositsQuery = `SELECT amount, date FROM deposits WHERE user_id = ? AND status = 'approved'`;
//             connection.query(approvedDepositsQuery, [userId], (err, approvedDeposits) => {
//                 if (err) {
//                     connection.release(); // Release connection back to the pool
//                     return res.json({ success: false, message: "Error fetching approved deposits." });
//                 }
  
//                 // Query pending deposits using user_id
//                 const pendingDepositsQuery = `SELECT amount, date FROM deposits WHERE user_id = ? AND status = 'pending'`;
//                 connection.query(pendingDepositsQuery, [userId], (err, pendingDeposits) => {
//                     connection.release(); // Release connection after the last query
  
//                     if (err) {
//                         return res.json({ success: false, message: "Error fetching pending deposits." });
//                     }
  
//                     // Return account details, approved deposits, and pending deposits
//                     res.json({
//                         success: true,
//                         full_name: user.full_name,
//                         username: user.username,
//                         created_at: user.created_at,
//                         balance: user.balance,
//                         approvedDeposits: approvedDeposits,
//                         pendingDeposits: pendingDeposits
//                     });
//                 });
//             });
//         });
//     });
//   });


























app.use((req, res, next) => {
    req.setTimeout(500000);  // Adjust as necessary (in milliseconds)
    next();
});


// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});