import express from 'express'
import dotenv from 'dotenv'
// import {prisma} from './prisma/client.js'
import  {router}  from './routes/authRouter.js'
import { testDBConnection } from './utils/helper.js'
import cookieParser from 'cookie-parser'
import cors from "cors"

dotenv.config()

const app = express()

// milldeware
app.use(express.json())
app.use(cookieParser());

app.use(cors({
  origin: 'http://localhost:3000', // ⚙️ change selon ton front
  credentials: true,               // autorise les cookies cross-site
}))

// routes
app.use('/api/auth', router)

// test 
app.get('/', (req, res) =>{
    res.send("bienvenu")
})



// Demarage du serveur
const PORT = process.env.PORT || 3000

app.listen(PORT, async ()=>{
    console.log(`Serveur démarré sur http://localhost:${PORT}`)
    await testDBConnection()
} )
