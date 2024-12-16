import express from 'express'
import { isAuthenticated, login, logout, register, resetPassword, sendResetPassword, sendVerifyOTP, verifyEmail } from '../controllers/authcontroller.js';
import userAuth from '../middleware/userAuth.js';
//charan
 const authRouter = express.Router();

authRouter.post('/register',register);
authRouter.post('/login',login)

authRouter.post('/logout',logout)
authRouter.post('/send-verify-otp',userAuth,sendVerifyOTP)
authRouter.post('/verify-account',userAuth,verifyEmail)
authRouter.post('/is-auth',userAuth,isAuthenticated)
authRouter.post('/send-restOTP',sendResetPassword)
authRouter.post('/reset-password',resetPassword)

export default authRouter