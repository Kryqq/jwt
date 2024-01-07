const express = require('express');
const crypto = require('crypto');
const cookie = require('cookie');
const authRouter = express.Router();
const { passwordSecret, fakeUser } = require('../auth/data');
const { getTokens, refreshTokenTokenAge } = require('./utils');

authRouter.post('/login', (req, res) => {
   const { login, password } = req.body;

   const hash = crypto.createHmac('sha256', passwordSecret).update(password).digest('hex');
   const isVerifiedPassword = hash === fakeUser.passwordHash;

   if (login !== fakeUser.login || !isVerifiedPassword) {
      return res.status(401).send('login fail');
   }
   const { accessToken, refreshToken } = getTokens(login);

   res.setHeader(
      'Set-Cookie',
      cookie.serialize('refreshToken', refreshToken, {
         httpOnly: true,
         maxAge: refreshTokenTokenAge,
      })
   );

   res.send({ accessToken });
});

authRouter.get('/logout', (req, res) => {
   res.setHeader(
      'Set-Cookie',
      cookie.serialize('reffreshToken', '', {
         httpOnly: true,
         maxAge: 0,
      })
   );
   res.sendStatus(200);
});

module.exports = authRouter;
