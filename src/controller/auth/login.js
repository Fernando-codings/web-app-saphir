
import { prisma } from '../../prisma/client.js';
import {  loginSchema} from '../../validation/authValidator.js';
import { hash, comparePassword} from '../../utils/helper.js';
import { generateJWT, generateRandomtoken } from '../../service/tokenService.js';



export const login = async ( req , res) => {
    try {
        
        
        // 1. Validation des données
        const {error , value} = loginSchema.validate(req.body, {abortEarly: false});
        if(error) return res.status(400).json({
            message: 'Données d\'entrée invalides',
            details: error.details.map(e => e.message)
        });

        const {email, password} = value;

        // 2. Recherche utilisateur par email en DB
        const user = await prisma.user.findUnique({
            where : {email},
            // Important pour l'étape 3.5
            include: {refresh_tokens: true} 
        });

        // 3. Vérification des identifiants
        if(!user) return unauthorizedResponse; // Échec (email)

        const isPassWordValid = await comparePassword(password, user.password_hash);
        if(!isPassWordValid) return unauthorizedResponse; // Échec (mot de passe) 
        
        // --- Authentification réussie ---
        
        // 3.5. Gestion et Nettoyage des Refresh Tokens Existants
        const MAX_ACTIVE_TOKENS = 5; 

        if (user.refresh_tokens.length >= MAX_ACTIVE_TOKENS) {
            const tokensSorted = user.refresh_tokens.sort((a, b) => a.created_at - b.created_at);
            const tokensToDeleteCount = user.refresh_tokens.length - MAX_ACTIVE_TOKENS + 1;
            console.log(tokensToDeleteCount)
            const tokensToDelete = tokensSorted.slice(0, tokensToDeleteCount);
            
            await prisma.refreshToken.deleteMany({
                where: {
                    id: {
                        in: tokensToDelete.map(token => token.id)
                    }
                }
            });
            console.log(`Nettoyage : ${tokensToDeleteCount} token(s) de rafraîchissement supprimé(s) pour l'utilisateur ${user.id}.`);
        }

        // 4. Génération du Refresh Token
        const refreshBrut = generateRandomtoken();
        const refreshHash = await hash(refreshBrut);
        const REFRESH_TOKEN_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;
        const expires_at = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_MS);

        // 5. Stockage du refresh token en base
        await prisma.refreshToken.create({
            data:{
                user_id : user.id,
                token_hash: refreshHash,
                token_version: 1, // Peut être ajusté si vous avez une version logicielle
                expires_at: expires_at
            }
        });

        // 6. Génération du Jeton d'Accès (Access Token)
        const accessToken = generateJWT(user.id , user.role, user.global_token_version);

        // 7. Définir le Refresh Token dans le cookie HTTP-only
        res.cookie('refreshToken', refreshBrut, { // Nom standardisé 'refreshToken'
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            expires: expires_at
        });

        // Envoie la réponse au client 
        return res.status(200).json({
            message: "Vous êtes connecté(e)",
            data: {
                user: user.id,
                name: user.name,
                email: user.email
            },
            token: accessToken, // Renommé 'accessToken' pour la clarté
            // SUPPRESSION: Ne pas renvoyer refreshBrut en JSON
        });

    } catch (error) {
        console.error("Erreur lors de la connexion:", error);
        return res.status(500).json({
            message: "Erreur interne du serveur",
        });
    }
};
