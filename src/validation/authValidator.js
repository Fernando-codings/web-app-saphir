import Joi from "joi";

//  validation de donner lors de l'inscriptions
export const registerSchema= Joi.object({
    name: Joi.string().min(3).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required()
})

// validations de donner lors de la connexion ( login)
export const loginSchema = Joi.object({
    email: Joi.string().email().max(50).required(),
    password: Joi.string().min(8).required()
})