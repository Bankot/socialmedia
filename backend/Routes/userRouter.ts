import express from "express"
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
export default router
