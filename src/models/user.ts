import mongoose, { Document, Schema } from "mongoose";
import { isEmail } from "validator";
import bcrypt from "bcrypt";
// Define the TypeScript interface for a User
interface IUser extends Document {
  firstname: string;
  lastname: string;
  email: string;
  password: string;
  isAdmin: boolean;
  isSubscriber: boolean;
}

// Utilisateur
const userSchema = new Schema<IUser>(
  {
    firstname: {
      type: String,
      required: [true, "Please provide your first name."],
    },
    lastname: {
      type: String,
      required: [true, "Please provide your last name."],
    },
    email: {
      type: String,
      required: [true, "Email address is required."],
      lowercase: true,
      unique: true,
      validate: {
        validator: function (value: string) {
          // Use the isEmail function from the validator package
          return isEmail(value);
        },
        message: "Please enter a valid email.",
      },
    },
    password: {
      type: String,
      required: [true, "Password is required."],
      minlength: [8, "Password must be at least 8 characters long."],
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
    isSubscriber: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);
userSchema.pre("save", async function (next) {
  const salt = await bcrypt.genSalt();
  this.password = await bcrypt.hash(this.password, salt);
  next();
});
const User = mongoose.model<IUser>("User", userSchema);

export { userSchema, User, IUser };
