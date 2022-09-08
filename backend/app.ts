import express from "express"
import logger from "./logger/logger"
import userRouter from "./Routes/userRouter"
import dotenv from "dotenv"
import mongoose from "mongoose"
import cookieParser from "cookie-parser"
dotenv.config()

const app = express()

app.use(cookieParser())
app.use(express.json())
app.use("/api", userRouter)

mongoose
	.connect(process.env.MONGO_URI!)
	.then(() => {
		logger.info("Connected to mongoDB!")
		app.listen(3000, () => {
			logger.info("Listening on port 3000...")
		})
	})
	.catch((err) => logger.error(err))
