import { prisma } from '../../prisma/client.js';
import { comparePassword, clearCookieAndRespond } from '../../utils/helper.js';

export const logout = async (req, res) => {
  const refreshTokenBrut = req.cookies.RefreshToken;

  if (!refreshTokenBrut) {
    return clearCookieAndRespond(res, 'Déconnexion réussie (aucun token trouvé)');
  }

  try {
    // 1️ On récupère tous les tokens existants (ou filtrer par user_id si tu le passes dans le JWT)
    const tokens = await prisma.refreshToken.findMany();

    // 2️ On cherche celui qui correspond au cookie reçu
    let tokenFound = null;

    for (const token of tokens) {
      const match = await comparePassword(refreshTokenBrut, token.token_hash);
      if (match) {
        tokenFound = token;
        break;
      }
    }

    // 3️ Si on a trouvé un token correspondant → suppression
    if (tokenFound) {
      await prisma.refreshToken.delete({ where: { id: tokenFound.id } });
      console.log(`✅ Token ${tokenFound.id} supprimé`);
    } else {
      console.warn('⚠️ Aucun token correspondant trouvé à supprimer');
    }

    // 4️ Effacement du cookie et réponse
    return clearCookieAndRespond(res, 'Déconnexion réussie');
  } catch (error) {
    console.error("❌ La déconnexion a échoué lors de la révocation DB:", error);
    return clearCookieAndRespond(
      res,
      "Erreur interne du serveur lors de la révocation du token. Cookie effacé.",
      500
    );
  }
};
