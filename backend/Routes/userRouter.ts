import express from "express"
import refreshTokenMiddleware from "../Middleware/refreshTokenMiddleware"
import {
	loginController,
	signupController,
	refreshToken,
	deleteRefreshTokens,
} from "../Controllers/userController"
const router = express.Router()

router.route("/signIn").post(loginController)
router.route("/signUp").post(signupController)
router.route("/signOut").post()
router.route("/getAllUsers").get()
router.route("/getUser").get()
router.route("/refreshToken").get(refreshToken).delete(deleteRefreshTokens)
router.route("/protected").get(refreshTokenMiddleware, (req, res) => {
	return res.send(req.accessToken)
})
export default router
