import { Router } from 'express';
import * as AuthController from '../controllers/auth.controller';

const authRouter = Router();
const authRoutes = (baseRouter: Router) => {
    baseRouter.use('/auth', authRouter);

    authRouter.post('/newUser', AuthController.newUser);
    authRouter.post('/login', AuthController.login);
};

export default authRoutes;
