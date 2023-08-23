import { injectable, inject } from 'inversify';
import express from 'express';
import { getUserByEmail, createUser } from '../db/users';
import { authentication, random } from '../helpers';

@injectable()
class AuthenticationController {
  constructor(
    @inject('express') private readonly express: express.Application,
  ) {}

  @Get('/login')
  async login(req: express.Request, res: express.Response) {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.sendStatus(400);
      }

      const user = await getUserByEmail(email).select('+authentication.salt +authentication.password');

      if (!user) {
        return res.sendStatus(400);
      }

      const expectedHash = authentication(user.authentication.salt, password);
      
      if (user.authentication.password !== expectedHash) {
        return res.sendStatus(403);
      }

      const salt = random();
      const sessionToken = authentication(salt, user._id.toString());

      user.authentication.sessionToken = sessionToken;
      await user.save();

      res.cookie('DENIZ-AUTH', sessionToken, { domain: 'localhost', path: '/' });

      return res.status(200).json(user).end();
    } catch (error) {
      console.log(error);
      return res.sendStatus(400);
    }
  }

  @Get('/register')
  async register(req: express.Request, res: express.Response) {
    try {
      const { email, password, username } = req.body;

      if (!email || !password || !username) {
        return res.sendStatus(400);
      }

      const existingUser = await getUserByEmail(email);
    
      if (existingUser) {
        return res.sendStatus(400);
      }

      const salt = random();
      const hashedPassword = authentication(salt, password);

      const user = await createUser({
        email,
        username,
        authentication: {
          salt,
          password: hashedPassword,
        },
      });

      return res.status(200).json(user).end();
    } catch (error) {
      console.log(error);
      return res.sendStatus(400);
    }
  }
}

export default AuthenticationController;
