import bcrypt from "bcrypt";
import { User } from "../models/User.js";

const resetPassword = async (req, res) => {
  const validatePassword = (password) => {
    return password.length >= 6; // Example: Password must be at least 6 characters
  };

  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).json({ message: "All fields are required" });
  }

  if (!validatePassword(newPassword)) {
    return res.status(400).json({ message: "Password too short" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the password with the hashed password
    user.password = hashedPassword;

    await user.save();
    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export { resetPassword };
