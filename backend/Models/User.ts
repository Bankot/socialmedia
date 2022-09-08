import mongoose from "mongoose"

// simplest user schema & model

type UserType = {
	email: string
	password: string
	refreshToken: string[]
}
const UserSchema = new mongoose.Schema<UserType>({
	email: {
		type: String,
		required: [true, "You have to insert email!"],
		unique: true,
	},
	password: {
		type: String,
		required: [true, "You have to insert password!"],
		minlength: [6, "Password must be at least 6 characters long!"],
	},
	refreshToken: [
		{
			type: String,
		},
	],
})
export const UserModel = mongoose.model<UserType>("User", UserSchema)
