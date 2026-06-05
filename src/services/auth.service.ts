import { createUser,findUserByEmail } from "../repository/user.repository.js";
import * as db from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export interface RegisterInput {
  email: string
  password: string
  username: string
  role?: string 
}
export interface loginInput {
  email: string
  password: string
}


export async function registerUser(pool:db.Pool, input:RegisterInput){
    const user=await findUserByEmail(pool,input.email);
    if(user){
        throw new Error("Email Already exists");
    }
    else{
        const pass=await bcrypt.hash(input.password,10);
        const newUser=await createUser(pool,input.email,pass,input.username,input.role??'user');
        return newUser;
    }
}

export async function loginUser(pool: db.Pool, input: loginInput, jwtSecret: string, accessTokenExpiry: string) {
    const user=await findUserByEmail(pool,input.email);
    if(user==null){
        throw new Error("User does not exist");
    }
    else{
        const pass=input.password;
        const comp=await bcrypt.compare(pass,user.password);
        if(comp){
            const tokens = generateTokens(user.id, user.role, jwtSecret, accessTokenExpiry)
            return {user,tokens};
        }
        else{
            throw new Error("Invalid Password");
        }
    }
}


export function generateTokens(userId: string,role: string,jwtSecret: string,accessTokenExpiry: string){
    const refreshToken=crypto.randomUUID();
    const accessToken=jwt.sign({userId,role},jwtSecret,{expiresIn:accessTokenExpiry}as jwt.SignOptions);
    return {accessToken,refreshToken};
}