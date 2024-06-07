import mongoose, { Document, Schema } from "mongoose";

interface IArtist extends Document {
  firstname: string;
  lastname: string;
  picture_url: string;
  genre: string;
  born_date: Date;
  born_city: string;
  died_date?: Date;
}

const ArtistSchema = new Schema<IArtist>(
  {
    firstname: {
      type: String,
      required: [true, "Please provide the artist's first name."],
    },
    lastname: {
      type: String,
      required: [true, "Please provide the artist's last name."],
    },
    picture_url: {
      type: String,
      // validate: {
      //   validator: function (v: string) {
      //     // Simple URL validation regex
      //     return /^(ftp|http|https):\/\/[^ "]+$/.test(v);
      //   },
      //   message: (props) =>
      //     `${props.value} is not a valid URL. Please enter a valid picture URL.`,
      // },
    },
    genre: {
      type: String,
      validate: {
        validator: function (v: string) {
          // Example: Check if genre is one of the predefined genres
          const allowedGenres = ["rock", "pop", "jazz", "classical"];
          return allowedGenres.includes(v.toLowerCase());
        },
        message: (props) =>
          `${props.value} is not a recognized genre. Please choose from rock, pop, jazz, classical.`,
      },
    },
    born_date: {
      type: Date,
      validate: {
        validator: function (v: any) {
          return v instanceof Date;
        },
        message: (props) =>
          `${props.value} is not a valid date. Please enter a valid date for the artist's birth date.`,
      },
    },
    born_city: { type: String },
    died_date: {
      type: Date,
      validate: {
        validator: function (v: any) {
          return v instanceof Date;
        },
        message: (props) =>
          `${props.value} is not a valid date. Please enter a valid date for the artist's died date.`,
      },
    },
  },
  { timestamps: true }
);

export default mongoose.model<IArtist>("Artist", ArtistSchema);
