import { createUser,findUserByEmail } from "../repository/user.repository.js";
import * as db from 'pg';
import bcrypt from 'bcrypt';


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

export async function loginUser(pool:db.Pool,input:loginInput) {
    const user=await findUserByEmail(pool,input.email);
    if(user==null){
        throw new Error("User does not exist");
    }
    else{
        const pass=input.password;
        const comp=await bcrypt.compare(pass,user.password);
        if(comp){
            return user;
        }
        else{
            throw new Error("Invalid Password");
        }
    }
}