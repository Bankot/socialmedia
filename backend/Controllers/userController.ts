import { Request, Response, NextFunction } from "express"
import { UserModel } from "../Models/User"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import logger from "../logger/logger"
import dotenv from "dotenv"
import signJwt from "../utils/jwtSign"
import cookieCreator from "../utils/cookieCreator"
dotenv.config()

const loginController = async (
	req: Request,
	res: Response,
	next: NextFunction
) => {
	// first get props from the body
	const { email, password } = req.body
	// make sure props exists
	if (!email || !password) return res.send("Please provide all needed data!")

	//here we are gonna start all the logic about sessions, tokens etc.

	// first let's check if user exists
	let foundUser = await UserModel.findOne({ email: email })
	// check if foundUser exists
	if (!foundUser || !foundUser._id)
		return res.send("Account for given email doesn't exist!")
	// compare given password with password in database
	bcrypt.compare(password, foundUser.password, async (err, response) => {
		// i know it's not the best error handling but its enough for now
		if (err) {
			logger.error(typeof err.message === "string" ? err.message : err)
			return res.status(404).send(err)
		}
		if (response) {
			// here we will send tokens
			// access token:
			const accessToken = signJwt.signAccessToken(foundUser!._id.toString())

			// refresh token:
			const refreshToken = signJwt.signRefreshToken(foundUser!._id.toString())

			if (!accessToken || !refreshToken) return res.send("Error occured!")

			// now we want to assign tokens to the cookies
			cookieCreator.addAccessTokenCookie(res, accessToken)
			cookieCreator.addRefreshTokenCookie(res, refreshToken)

			// then we are replacing the refresh token in db
			// atm users can have only one refresh token but it could be also array of tokens
			// its more safe, but if I implemented way of recognizing which one is from what IP or something,
			// i could implement multiple tokens
			try {
				await UserModel.findOneAndUpdate(
					{ email: email },
					{ $push: { refreshToken: refreshToken } }
				)
			} catch (err: any) {
				logger.error(typeof err.message === "string" ? err.message : err)
				return res.status(400).send("Some error occured!")
			}

			return res.json({ accessToken })
		} else return res.status(400).send("Invalid password!")
	})
}
const changePasswordController = async (
	req: Request,
	res: Response,
	next: NextFunction
) => {
	// before running this controller we want to run auth middleware, to make sure that user is authenticated
	const accessToken = req.accessToken
	// anyways im gonna make sure it exists, just in case i made any mistakes in refreshTokens middleware
	if (!accessToken) return res.status(401).send("Unauthorized!")
	// now let's check if user knows old password and then send a brand new password to the server!
}

const signupController = async (
	req: Request,
	res: Response,
	next: NextFunction
) => {
	// first get props from the body
	const { email, password } = req.body
	// make sure props exists
	if (!email || !password)
		return res.status(400).send("Please provide all needed data!")

	//here we are gonna start all the logic about sessions, tokens etc.

	// first let's check if user for given email exists
	let exists = await UserModel.findOne({ email: email })
	if (exists)
		return res.status(400).send("Account for given email already exists!")

	//generate salt
	const salt = await bcrypt.genSalt(Number(process.env.SALT))
	// ofc we are gonna store hashed passwords in our db
	try {
		await UserModel.create({
			email: email,
			password: await bcrypt.hash(password, salt),
		})
		res.send("Succesfully added a user!")
		// then redirect to login page, or send request to /login
	} catch (err: any) {
		logger.error(typeof err.message === "string" ? err.message : err)
		return res.status(400).send(err)
	}
}

const refreshToken = async (
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

			// if that's valid jwt, lets check if user ID signed in this jwt didn't remove that refresh token from db record

			let foundUser = await UserModel.findOne({ _id: decoded._id })
			// if theres no record for that token in db, redirect to login page
			if (!foundUser)
				return res.status(401).send("This token isnt matching any user!!")

			if (foundUser.refreshToken.includes(refreshToken)) {
				// finally, lets create a new access token, and push it to the browser as a cookie
				let accessToken = signJwt.signAccessToken(decoded._id)
				if (accessToken) {
					cookieCreator.addAccessTokenCookie(res, accessToken)
					res.send({
						status: "OK",
						msg: "Succesfully fefreshed token!!",
						decoded,
					})
				} else {
					// that's the case when jwt signing fails, try catch block in utils function should be upgraded in the future!
					res.status(400).send("Some error occured!")
				}
			} else {
				res.status(401).send("This session is no longer valid!")
			}
		}
	)
}
const deleteRefreshTokens = async (
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

			// if that's valid jwt, lets check if user ID signed in this jwt didn't remove that refresh token from db record

			let foundUser = await UserModel.findOne({ _id: decoded._id })
			// if theres no record for that token in db, redirect to login page
			if (!foundUser)
				return res.status(401).send("This token isnt matching any user!!")

			if (foundUser.refreshToken.includes(refreshToken)) {
				await UserModel.findOneAndUpdate(
					{ _id: decoded._id },
					{ refreshToken: [] }
				)
				return res.send("Succesfully deleted all logged sessions!")
			} else {
				return res.status(401).send("Unauthorized")
			}
		}
	)
}
export { loginController, signupController, refreshToken, deleteRefreshTokens }
