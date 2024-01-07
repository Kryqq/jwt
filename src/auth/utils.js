const jwt = require('jsonwebtoken');

const signatureAccess = 'MySuP3R_z3kr3t_access';
const signatureRefresh = 'MySuP3R_z3kr3t_refresh';

const accessTokenAge = 10; 
const refreshTokenTokenAge = 60 * 60; 

const getTokens = (login) => ({
   accessToken: jwt.sign({ login }, signatureAccess, {
      expiresIn: `${accessTokenAge}s`,
   }),
   refreshToken: jwt.sign({ login }, signatureRefresh, {
      expiresIn: `${refreshTokenTokenAge}s`,
   }),
});

module.exports = {
   getTokens,
   refreshTokenTokenAge,
};
