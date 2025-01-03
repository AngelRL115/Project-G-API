import { Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import prisma from '../prisma/prisma'
import { StatusCodes } from 'http-status-codes'
import * as dotenv from 'dotenv'
import bcrypt from 'bcrypt'
import logger from '../logger/logger'
dotenv.config()

interface User{
    name: string
    lastname: string
    email: string
    username: string
    password: string
    tel: string
    rol: number
}

//configurar jwt y passport para poder trabajar con ellos
// crear nueva branch para jwt y passport cuando se haga la ruta de login

export const newUser = async (req: Request, res: Response) => {
    const { name, lastname, email, username, password, tel } = req.body;
    let responseStatus = StatusCodes.OK;
    let responseContent;

    try {
        console.log(req.body)
        if (!name || !lastname || !email || !username || !password || !tel) {
            responseStatus = StatusCodes.BAD_REQUEST;
            responseContent = { error: 'All fields are required' };
            logger.warn(`[POST] Missing required fields: ${JSON.stringify(req.body)}`);
            return res.status(responseStatus).send(responseContent);
        }

        const existingEmail = await prisma.user.findFirst({ where: { email } });
        const existingUsername = await prisma.user.findFirst({ where: { username } });

        if (existingEmail) {
            responseStatus = StatusCodes.CONFLICT;
            responseContent = { error: 'Email already assigned to an account' };
            logger.info(`[POST] Email already in use: ${email}`);
            return res.status(responseStatus).send(responseContent);
        }

        if (existingUsername) {
            responseStatus = StatusCodes.CONFLICT;
            responseContent = { error: 'Username already taken' };
            logger.info(`[POST] Username already taken: ${username}`);
            return res.status(responseStatus).send(responseContent);
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user: User = {
            name,
            lastname,
            email,
            username,
            password: hashedPassword,
            tel,
            rol: 1
        };

        const newUser = await prisma.user.create({
            data: {
                name: user.name,
                lastname: user.lastname,
                email: user.email,
                username: user.username,
                password: user.password,
                tel: user.tel,
                rol_idrol: user.rol,
            }
        });

        responseContent = { message: 'New user registered successfully', userId: newUser.iduser, email: newUser.email };
        logger.info(`[POST] User created: ${newUser.iduser}, Email: ${newUser.email}`);
    } catch (error) {
        logger.error(`[POST] auth.controller/newUser. Error registering user: ${error}`);
        responseStatus = StatusCodes.INTERNAL_SERVER_ERROR;
        responseContent = { error: `Internal server error: ${error}` };
        return res.status(responseStatus).send(responseContent);
    }

    return res.status(responseStatus).send(responseContent);
};

export const login = async (req: Request, res: Response) => {}
