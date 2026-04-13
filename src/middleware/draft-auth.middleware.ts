import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/user.model';

interface AuthRequest extends Request {
  user?: any;
}

// Custom middleware for draft operations that handles both authenticated and unauthenticated users
export const draftAuth = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const sessionId = req.headers['x-session-id'] as string;

    // If no token and no session ID, return error
    if (!token && !sessionId) {
      return res.status(400).json({
        success: false,
        message: 'Authentication token or session ID required',
      });
    }

    // If token is provided, verify it and set user
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret') as any;
        const user = await User.findById(decoded.userId).select('-password');

        if (user) {
          req.user = { userId: user._id, ...decoded };
        }
      } catch (tokenError) {
        // Token is invalid, but we might still have a session ID
        if (!sessionId) {
          return res.status(401).json({
            success: false,
            message: 'Invalid authentication token',
          });
        }
        // Continue without user if we have session ID
      }
    }

    // If we have a session ID but no user, that's fine for unauthenticated users
    next();
  } catch (error) {
    console.error('Draft auth middleware error:', error);
    res.status(500).json({
      success: false,
      message: 'Authentication error',
    });
  }
};
