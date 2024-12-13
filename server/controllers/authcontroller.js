import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import userModel from '../models/UserModel.js';
import transporter from '../config/nodemailer.js';

export const register = async(req,res)=>{
    const {name,email,password}= req.body;

    if(!name || !email || !password ){
        return res.json({success:false,message:'Missing details'})
    }

    try {

        const existingUser = await userModel.findOne({email});

        if(existingUser){
            return res.json({success:false,message:'user alredy exists'})
        }

        const hash = await bcrypt.hash(password,10);
        const user = new userModel({
            name:name,
            email:email,
            password:hash
        })
        await user.save();

        const token = jwt.sign({
            id:user._id,
        },process.env.JWT_KEY,{expiresIn:'7d'})

        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production'?'none':'strict',
            maxAge:7*24*60*60*1000
        });
        //send email
        const mailoptions={
            from:process.env.SENDER_EMAIL,
            to:email,
            subject:'welcome to out website',
            text:`welcome to out website ${name}.`,

        }

        await transporter.sendMail(mailoptions);

        return res.json({
            success:true
           })
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

export const login = async (req, res) => {
    const { name, email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
        return res.json({
            success: false,
            message: "Login failed due to missing email or password",
        });
    }

    try {
        // Find the user in the database
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({
                success: false,
                message: "Invalid email",
            });
        }

        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.json({
                success: false,
                message: "Invalid password",
            });
        }

        // Generate a JWT token
        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_KEY,
            { expiresIn: '7d' }
        );

        // Set the token in a cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        // Send success response
        return res.json({
            success: true,
        });

    } catch (error) {
        // Handle errors
        return res.json({
            success: false,
            message: error.message,
        });
    }
};


export const logout = async (req,res)=>{
    try {
        res.clearCookie('token',{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production'?'none':'strict'
            
        })

        return res.json({
            success:true,
            message:'logout sucess'
        })
    } catch (error) {
        return res.json(
            {
                success:false,
                message:error.message
            }
        )
    }
}

export const sendVerifyOTP = async(req,res)=>
{
    try {
        const{ userId} = req.body;
        const user = await userModel.findById(userId)

        if(user.idverified){
            return res.json({
                success:false,
                message:"already verified"
            })
        }

    const OTP=String(Math.floor(100000+Math.random()*900000))
        
        user.verifyOTP =OTP;


        user.expverifyOTP=Date.now()+24*60*60*1000;

        await user.save();
        
        //send mail

        const mailoption = {
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:'OTP verified to our website',
            text:`your OTP is ${OTP} verify your account using this OTP`,
        }
        
        await transporter.sendMail(mailoption) 
        return res.json({
            success:true,
            message:"verification sent"
        })

    } catch (error) {
        return res.json({
            success:false,
            message:'error sending OTP'
        })
    }
}

export const verifyEmail = async(req,res)=>{
    
        const {userId,OTP} = req.body;

        if(!userId || !OTP )
        {
            return res.json({
                success:false,
                message:"failed in verify email"
            })
        }
        try {
        const user = await userModel.findById(userId)
    } catch (error) {
        return res.json({
            success:false,
            message:"failed in verify email"
        })
    }
}