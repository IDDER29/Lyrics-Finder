import mongoose, { Document, Schema } from "mongoose";

interface IVerificationCode extends Document {
  email: string;
  code: string;
  expires: Date;
}

const verificationCodeSchema = new Schema<IVerificationCode>({
  email: {
    type: String,
    required: true,
  },
  code: {
    type: String,
    required: true,
  },
  expires: {
    type: Date,
    required: true,
  },
});

const VerificationCode = mongoose.model<IVerificationCode>("VerificationCode", verificationCodeSchema);

export default VerificationCode;
