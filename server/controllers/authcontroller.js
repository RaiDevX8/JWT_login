import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import userModel from '../models/UserModel.js';

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

        return res.json({
            success:true
           })
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

export const login =async(req,res)=>{
    const {name,email,password}= req.body;

    if(!email || !password)
    {
        res.json({
            success:false,
            message:"login fail due to wrong email and password"
        })

        try {
            const user= await userModel.findOne({email});
            if(!user)
            {
                return res.json({
                    success:false,
                    message:"invalid email"
                })
            }
            
            const isMatch = await bcrypt.compare(password,user.password);

            if(!isMatch)
            {
                res.json({
                    success:false,
                    message:"invalid password"
                })
            }

            //if user is there generate token

            const token = jwt.sign({
               id:user._id,
            },process.env.JWT_KEY,{expiresIn:'7d'})


           res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production'?'none':'strict',
            maxAge:7*24*60*60*1000
           })

           return res.json({
            success:true
           })

        } catch (error) {
            res.json({
                success:false,
                message:error.message
            })
        }
    }
}

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