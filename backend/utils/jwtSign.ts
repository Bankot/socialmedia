import jwt from "jsonwebtoken"
import dotenv from "dotenv"
import logger from "../logger/logger"
dotenv.config()

const signAccessToken = (_id: string) => {
	try {
		return jwt.sign({ _id }, process.env.ACCESS_SECRET!, { expiresIn: "5m" })
	} catch (err: any) {
		logger.error(typeof err.message === "string" ? err.message : err)
		return null
	}
}
const signRefreshToken = (_id: string) => {
	try {
		return jwt.sign({ _id }, process.env.REFRESH_SECRET!, { expiresIn: "1y" })
	} catch (err: any) {
		logger.error(typeof err.message === "string" ? err.message : err)
		return null
	}
}
export default { signAccessToken, signRefreshToken }
