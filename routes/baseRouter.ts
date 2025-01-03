import express from 'express'
import authRoutes from './auth.routes'


const baseRouter = express.Router()

authRoutes(baseRouter)

export default baseRouter