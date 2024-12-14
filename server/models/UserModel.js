import mongoose from "mongoose";

const User = new mongoose.Schema({
    name:{type:String , required:true},
    email:{type:String, required:true, unique:true},
    password:{type:String, required :true},
    verifyOTP:{type:String, default:''},
    expverifyOTP:{type:Number, default:0},
    isverified:{type:Boolean, default:false},
    resetOTP:{type:String,default:""},
    expresetOTP:{type:Number,default:0},
})

const userModel =mongoose.models.user|| mongoose.model('user',User);

export default userModel;