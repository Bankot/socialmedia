import mongoose from "mongoose"

// simplest user schema & model

type CommentType = {
	creator: string
	content: string
	createdAt: string
}
const CommentSchema = new mongoose.Schema<CommentType>({
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
})
export const CommentModel = mongoose.model<CommentType>(
	"Comment",
	CommentSchema
)
