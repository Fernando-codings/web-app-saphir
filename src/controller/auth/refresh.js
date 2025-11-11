import { prisma } from '../../prisma/client.js';
import { hash,  clearRefreshCookie, setRefreshCookie} from '../../utils/helper.js';
import { generateJWT, generateRandomtoken } from '../../service/tokenService.js';


// refresh
export const refreshToken = async (req , res) =>{

    // 1. Récupération du RefreshToken depuis cookie 
    const refreshTokenBrut = req.cookies.refreshToken; // Nom standardisé

    if (!refreshTokenBrut){
        // Si le token est manquant, effacer par sécurité et renvoyer 401
        clearRefreshCookie(res); 
        return res.status(401).json({
            status: "Non autorisé",
            message: "Jeton manquant ou session expirée. Veuillez vous reconnecter."
        });
    }

    try {
        // 2. Hachage du token brut pour la recherche en base de données
        const refreshHash = await hash(refreshTokenBrut);

        // 3. Recherche le token dans la BD
        const findToken = await prisma.refreshToken.findUnique({
            where: {token_hash: refreshHash},
            include: {
                user:{
                    select: {
                        id: true, role: true, global_token_version: true
                    }
                }
            }
        });

        // 4. Vérification et Révocation immédiate (Token Rotation)
        
        // Token non trouvé (invalide ou déjà révoqué)
        if (!findToken) {
            clearRefreshCookie(res);
            return res.status(401).json({
                status : "Non autorisé",
                message : "Session invalide. Veuillez vous reconnecter."
            });
        }
        
        // Vérification de l'expiration
        if (findToken.expires_at < new Date()) {
            // Token expiré, le supprimer de la DB, effacer le cookie et refuser l'accès.
            await prisma.refreshToken.delete({ where: { id: findToken.id} });
            clearRefreshCookie(res);
            return res.status(401).json({
                status : "Non autorisé",
                message : "Votre session a expiré. Veuillez vous reconnecter."
            });
        }
        
        // RÉVOCATION DE L'ANCIEN TOKEN (Rotation !)
        // On supprime l'entrée que nous venons d'utiliser pour qu'elle ne soit plus réutilisable.
        await prisma.refreshToken.delete({ where: { id: findToken.id} });

        // 5. Génération et Stockage du NOUVEAU Refresh Token
        const newRefreshBrut = generateRandomtoken();
        const newRefresHash = await hash(newRefreshBrut);
        
        const REFRESH_TOKEN_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;
        const newExpirate = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_MS);

        await prisma.refreshToken.create({
            data:{
                user_id: findToken.user.id,
                token_hash: newRefresHash,
                expires_at: newExpirate
            }
        });

        // 6. Génération du Jeton d'Accès (Access Token)
        // Accès à la version via findToken.user
        const newAccesToken = generateJWT(
            findToken.user.id, 
            findToken.user.role, 
            findToken.user.global_token_version // Accès corrigé via findToken.user
        );

        // 7. Mise à jour du cookie et réponse
        setRefreshCookie(res, newRefreshBrut, newExpirate); // Utilisation de l'utilitaire

        return res.status(200).json({
            message: "Access Token rafraîchi avec succès",
            token: newAccesToken
        });

    } catch (error) {
        console.error("❌ Erreur lors du rafraîchissement du token:", error);
        
        // SECURITÉ : Effacer le cookie même en cas d'erreur interne
        clearRefreshCookie(res); 
        return res.status(500).json({
            message: "Erreur interne du serveur. Reconnexion requise."
        });
    }
};