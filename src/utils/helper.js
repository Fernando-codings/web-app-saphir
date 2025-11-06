import { prisma } from '../prisma/client.js'
import bcrypt from 'bcrypt'
// import crypto from 'crypto'
// connection base de donner
export const testDBConnection = async () =>{
    try{
        await prisma.$connect()
        console.log("Conneted to DATABSE Postgrl via Prisma")
    }catch(err){
        console.log("Faild to connect DATABE", err)
    }
}

// hash le mot de passe  et refrsh
export const hash = ( item ) =>{
    return bcrypt.hash(item, 10)
} 

