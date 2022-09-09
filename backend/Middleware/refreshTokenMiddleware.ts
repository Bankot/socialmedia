import { Request, Response, NextFunction } from "express"
import { UserModel } from "../Models/User"
import jwt from "jsonwebtoken"
import dotenv from "dotenv"
import logger from "../logger/logger"
import cookieCreator from "../utils/cookieCreator"
import signJWT from "../utils/jwtSign"

dotenv.config()

const refreshTokenMiddleware = async (
	req: Request,
	res: Response,
	next: NextFunction
) => {
	// check if user is sending cookie with refresh token

	if (!req.cookies.refreshToken) {
		console.log(req.cookies)
		return res.status(401).send("Log in!")
	}
	const { refreshToken } = req.cookies

	// let's verify if that's valid JWT refresh token
	jwt.verify(
		refreshToken,
		process.env.REFRESH_SECRET!,
		async (err: any, decoded: any) => {
			// dummy error handler
			if (err) {
				logger.error(typeof err.message === "string" ? err.message : err)
				return res.status(400).send(err)
			}
			// if that's not valid JWT, lets redirect to login page

			if (!decoded || !decoded._id)
				return res.status(401).send("Please log in!")

			// if that's valid jwt, lets check if its present in db record
			let foundUser = await UserModel.findOne({ _id: decoded._id })
			// if theres no record for that token in db, redirect to login page
			if (!foundUser)
				return res.status(401).send("This token isnt matching any user!!")

			if (foundUser.refreshToken.includes(refreshToken)) {
				// finally, lets create a new access token, and push it to the browser as a cookie
				let accessToken = signJWT.signAccessToken(decoded._id)
				if (accessToken) {
					cookieCreator.addAccessTokenCookie(res, accessToken)
					next()
				} else {
					return res.status(401).send("Unauthorized")
				}
			} else {
				return res.send("You are not authorized!")
			}
		}
	)
}
export default refreshTokenMiddleware
