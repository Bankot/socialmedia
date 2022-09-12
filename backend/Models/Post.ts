import mongoose from "mongoose"

// simplest user schema & model

type PostType = {
	creator: string
	content: string
	createdAt: string
	comments?: string[]
}
const PostSchema = new mongoose.Schema<PostType>({
	creator: {
		type: String,
		required: true,
	},
	content: {
		type: String,
		required: true,
		minlength: [6, "Please enter longer post!"],
	},
	createdAt: [
		{
			type: String,
		},
	],
	comments: [
		{
			type: String,
		},
	],
})
export const UserModel = mongoose.model<PostType>("Post", PostSchema)
