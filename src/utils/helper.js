import { prisma } from '../prisma/client.js'
import bcrypt from 'bcrypt'

// connection base de donner
export const testDBConnection = async () =>{
    try{
        await prisma.$connect()
        console.log("Conneted to DATABSE Postgrl via Prisma")
    }catch(err){
        console.log("Faild to connect DATABE", err)
    }
}

// hash le mot de passe  et refresh
export const hash = ( item ) =>{
    return bcrypt.hash(item, 10)
} 

// comparer le password
export const comparePassword = (passwordBrut, passwordHash) =>{
    return bcrypt.compare(passwordBrut, passwordHash)
}

// efface le cookie et renvoyer la reponse
export const clearCookieAndRespond =( res, message , status=200) =>{
    res.clearCookie("RefreshToken", {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: "strict",
        maxAge: new Date(0)
    });

    return res.status(status).json({
        message: message
    })
}


// Fonction utilitaire pour effacer le cookie (à placer en dehors du contrôleur)
export const clearRefreshCookie = (res) => {
    // Note: Utiliser res.clearCookie() si disponible (Express)
    res.cookie('refreshToken', '', { // Utilisation du nom standardisé 'refreshToken'
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        expires: new Date(0), // Effacement immédiat
    });
};

// Fonction utilitaire pour définir le cookie (pour l'étape 7)
export const setRefreshCookie = (res, token, expiryDate) => {
    res.cookie('refreshToken', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        expires: expiryDate,
    });
};