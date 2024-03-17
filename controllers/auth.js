const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("../models/User");

// Register a new user
const register = async (req, res, next) => {
  const { username, email, password } = req.body;

  try {
    const user = new User({ username, email, password });
    await user.save();
    res.json({ message: "Registration successful" });
  } catch (error) {
    next(error);
  }
};

// Login with an existing user
const login = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const passwordMatch = await user.comparePassword(password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Incorrect password" });
    }

    const token = jwt.sign({ userId: user._id }, "mysecretkey", {
      expiresIn: "1 hour",
    });
    res.json({ token });
  } catch (error) {
    next(error);
  }
};

// Forgot Password
const forgotPassword = async (req, res, next) => {
  const { email } = req.body;

  try {
    console.log("Requested email:", email);

    const user = await User.findOne({ email:email });
    if (!user) {
      console.log("User not found");
      return res.status(404).json({ message: "User not found" });
    }

    // Generate a unique password reset token
    const resetToken = jwt.sign({ userId: user._id }, "mysecret", {
      expiresIn: "1 hour",
    });

    console.log("Reset token:", resetToken);
    res.json({ resetToken, userId: user._id });// Send the reset token to the client
  } catch (error) {
    console.error("Error in forgotPassword:", error);
    next(error);
  }
};


const resetPassword = async (req, res, next) => {
  const { token, newPassword } = req.body;

  try {
    // Verify and decode the JWT token
    const decoded = jwt.verify(token, "mysecret");

    // Check if token has expired
    if (decoded.exp < Date.now() / 1000) {
      return res.status(400).json({ message: "Token has expired" });
    }

    // Find user by user ID from token
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password in the database
    user.password = hashedPassword;
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ message: "Failed to reset password" });
  }
};

module.exports = { register, login, forgotPassword, resetPassword };
