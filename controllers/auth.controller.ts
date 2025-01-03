import { Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import prisma from '../prisma/prisma'
import { StatusCodes } from 'http-status-codes'
import * as dotenv from 'dotenv'
import bcrypt from 'bcrypt'
import logger from '../logger/logger'
dotenv.config()

interface User {
	name: string
	lastname: string
	email: string
	username: string
	password: string
	tel: string
	rol: number
}

export const newUser = async (req: Request, res: Response) => {
	const { name, lastname, email, username, password, tel } = req.body
	let responseStatus = StatusCodes.CREATED
	let responseContent

	try {
		console.log(req.body)
		if (!name || !lastname || !email || !username || !password || !tel) {
			responseStatus = StatusCodes.BAD_REQUEST
			responseContent = { error: 'All fields are required' }
			logger.warn(`[POST] Missing required fields: ${JSON.stringify(req.body)}`)
			return res.status(responseStatus).send(responseContent)
		}

		const existingEmail = await prisma.user.findFirst({ where: { email } })
		const existingUsername = await prisma.user.findFirst({ where: { username } })

		if (existingEmail) {
			responseStatus = StatusCodes.CONFLICT
			responseContent = { error: 'Email already assigned to an account' }
			logger.info(`[POST] Email already in use: ${email}`)
			return res.status(responseStatus).send(responseContent)
		}

		if (existingUsername) {
			responseStatus = StatusCodes.CONFLICT
			responseContent = { error: 'Username already taken' }
			logger.info(`[POST] Username already taken: ${username}`)
			return res.status(responseStatus).send(responseContent)
		}

		const hashedPassword = await bcrypt.hash(password, 10)
		const user: User = {
			name,
			lastname,
			email,
			username,
			password: hashedPassword,
			tel,
			rol: 2,
		}

		const newUser = await prisma.user.create({
			data: {
				name: user.name,
				lastname: user.lastname,
				email: user.email,
				username: user.username,
				password: user.password,
				tel: user.tel,
				rol_idrol: user.rol,
			},
		})

		responseContent = { message: 'New user registered successfully', userId: newUser.iduser, email: newUser.email }
		logger.info(`[POST] User created: ${newUser.iduser}, Email: ${newUser.email}`)
	} catch (error) {
		logger.error(`[POST] auth.controller/newUser. Error registering user: ${error}`)
		responseStatus = StatusCodes.INTERNAL_SERVER_ERROR
		responseContent = { error: `Internal server error: ${error}` }
		return res.status(responseStatus).send(responseContent)
	}

	return res.status(responseStatus).send(responseContent)
}

export const login = async (req: Request, res: Response) => {
	const { credential, password } = req.body
    let responseStatus = StatusCodes.OK
    let responseContent

    try {
        if (!credential) {
			responseStatus = StatusCodes.BAD_REQUEST
			responseContent = { error: 'Email or username missing' }
			logger.warn(`[POST] auth.controller/login. Missing credential.`)
            return res.status(responseStatus).send(responseContent)
		}

        if (!password) {
			responseStatus = StatusCodes.BAD_REQUEST
			responseContent = { error: 'Password is missing for this user' }
			logger.warn(`[POST] auth.controller/login. Missing password.`)
            return res.status(responseStatus).send(responseContent)
		}

        // Log when credential is received
        logger.info(`[POST] auth.controller/login. Attempting login with credential: ${credential}`)

        const credentialToLogin = await prisma.user.findFirst({
            where: {
                OR: [{email: credential}, {username: credential}]
            }
        })

        if (!credentialToLogin) {
			responseStatus = StatusCodes.BAD_REQUEST
			responseContent = { error: 'There is no account associated to this username or email' }
			logger.warn(`[POST] auth.controller/login. No user found with credential: ${credential}`)
            return res.status(responseStatus).send(responseContent)
		}

        const isValidPassword = await bcrypt.compare(password, credentialToLogin.password)
        
        if (!isValidPassword) {
			responseStatus = StatusCodes.UNAUTHORIZED
			responseContent = { error: 'Invalid credentials' }
			logger.warn(`[POST] auth.controller/login. Invalid password for user: ${credentialToLogin.username || credentialToLogin.email}`)
            return res.status(responseStatus).send(responseContent)
		}
        
        const payloadForPassport = {
            iduser: credentialToLogin.iduser,
            username: credentialToLogin.username,
            email: credentialToLogin.email,
        }

        const token = jwt.sign(payloadForPassport, process.env.JWT_SECRET!, {expiresIn: '1h'})
        
        responseContent = {token}
        // Log success
        logger.info(`[POST] auth.controller/login. User ${credentialToLogin.username || credentialToLogin.email} logged in successfully.`)

    } catch (error) {
        logger.error(`[POST] auth.controller/login. Error trying to login: ${error}`)
		responseStatus = StatusCodes.INTERNAL_SERVER_ERROR
		responseContent = { error: `Internal server error: ${error}` }
		return res.status(responseStatus).send(responseContent)
    }
    return res.status(responseStatus).send(responseContent)
}
