import express from 'express'
import { login, logout, register, sendVerifyOTP, verifyEmail } from '../controllers/authcontroller.js';
import userAuth from '../middleware/userAuth.js';
//charan
 const authRouter = express.Router();

authRouter.post('/register',register);
authRouter.post('/login',login)

authRouter.post('/logout',logout)
authRouter.post('/send-verify-otp',userAuth,sendVerifyOTP)
authRouter.post('/verify-account',userAuth,verifyEmail)

export default authRouter