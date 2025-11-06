import jwt from 'jsonwebtoken'
import crypto from "crypto"


// generation de token
export const generateJWT = (id , role, version) => {
    const payload = {id, role, version}
    const secret = process.env.JWT_SECRET
    const options = {expiresIn: process.env.JWT_ACCESS_EXPIRATION}
    return jwt.sign(payload , secret, options)

}

// Génération d'un refresh token aléatoire
export const generateRandomtoken = () =>{
    return crypto.randomBytes(32).toString('hex')
}
