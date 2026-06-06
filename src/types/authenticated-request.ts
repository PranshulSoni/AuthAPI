import { Request } from 'express';
import { JwtPayload } from 'jsonwebtoken';

export interface AuthPayload extends JwtPayload {
    userId: string
    role: string
    isVerified: boolean
}

export interface AuthenticatedRequest extends Request {
    user?: AuthPayload
}
