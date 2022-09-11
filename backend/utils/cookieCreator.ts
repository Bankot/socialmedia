import { Response } from "express"

const addRefreshTokenCookie = (res: Response, token: string) => {
	res.cookie("refreshToken", token, {
		httpOnly: true,
		secure: true,
		maxAge: 365 * 24 * 60 * 60 * 1000, //1y
	})
}
const addAccessTokenCookie = (res: Response, token: string) => {
	res.cookie("accessToken", token, {
		httpOnly: true,
		secure: true,
		maxAge: 1 * 60 * 1000, //1m
	})
}
export default { addAccessTokenCookie, addRefreshTokenCookie }
