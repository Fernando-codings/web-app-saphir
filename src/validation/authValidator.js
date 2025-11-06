import Joi from "joi";

export const registerSchema= Joi.object({
    name: Joi.string().min(3).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(12).required()
})

