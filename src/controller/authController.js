import { prisma } from '../prisma/client.js';
import { registerSchema } from '../validation/authValidator.js';
import { hash } from '../utils/helper.js';
import { generateJWT, generateRandomtoken } from '../service/tokenService.js';

// inscription de l'utlisateur
export const register = async (req, res) => {

  try {
    // 1. Validation des données
    const { error, value } = registerSchema.validate(req.body, { abortEarly: false });
    if (error) {
      return res.status(400).json({
        message: "Invalid input data",
        details: error.details.map(e => e.message),
      });
    }
    
    const { name, email, password } = value;

    // 2. Vérification de l'existence de l'email
    const existingEmail = await prisma.user.findUnique({ where: { email } });
    if (existingEmail) {
      return res.status(409).json({ message: "Email already exists" });
    }
    // 3. Préparation des données de sécurité
    const password_hash = await hash(password); 
    const refreshBrut = generateRandomtoken(); // Jeton non haché, à envoyer au client
    const refreshHash = await hash(refreshBrut); // Jeton haché, à stocker en base
    const REFRESH_TOKEN_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;
    const expires_at = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_MS) // 30 jours


  // 4. Création de l'utilisateur et du Refresh Token (Écriture Imbriquée)
  // Les deux sont créés et liés en une seule opération de base de données.
  const user = await prisma.user.create({
    data:{
      name,
      email,
      password_hash,
      provider: "local",
      role: 'user',
      refresh_tokens:{
        create:{
          token_hash: refreshHash,
          token_version: 1,
          expires_at: expires_at
        }
      }
    }
  })

  
   
   // 5. Accorde un jeton JWT aux user (Access Token)
    const token = generateJWT(user.id, user.role, user.global_token_version);

  // 6. Définition du Refresh Token dans un cookie HTTP-Only sécurisé
    res.cookie('refreshToken', refreshBrut, {
        httpOnly: true, // Empêche l'accès via JavaScript (protection XSS)
        secure: process.env.NODE_ENV === 'production', // N'envoyer qu'en HTTPS en production
        sameSite: 'strict', // Bonne pratique CSRF
        expires: expires_at, // Fait correspondre l'expiration du cookie à celle en DB
    });

  // 7. Envoi de la réponse de succès 
    return res.status(201).json({
      message: "Inscription réussie",
      user: { id: user.id, name: user.name, email: user.email },
      token,
      refreshToken: refreshBrut, // ← à envoyer via cookie HTTP-only
    });

  } catch (err) {
    console.error("❌ Erreur lors de l'inscription:", err);
    return res.status(500).json({ message: "Erreur interne du serveur" });
  }
};


// login 

// export const login = ( res , req) =>{
//   try {
    
//   } catch (error) {
    
//   }
// }
