const jwt = require('jsonwebtoken');
const config = require('../config');
const secret = config.jwt.secret;
const error = require('../utils/error')

function sign(data) {
    return jwt.sign(data, secret);
}

function verify(token) {
    return jwt.verify(token,secret);
}

const check = {
    own: function( req, owner ) {
        const decoded = decodeHeader( req )
        if ( decoded.id !== owner ) throw error(`You don't have the correct permissions to perform this action`, 401)
    },
    logged: function( req ) {
        decodeHeader( req )
    }
}

function getToken( auth ) {
    if ( !auth ) throw new Error('The token has not been provided')
    if ( auth.indexOf('Bearer ') === -1 ) throw new Error('Invalid Format')
    let token = auth.replace('Bearer ', '')
    return token
}

function decodeHeader( req ) {
    const authorization = req.headers.authorization ?? ''
    const token = getToken( authorization )
    const decoded = verify( token )

    req.user = decoded
    return decoded
}

module.exports = {
    sign,
    check,
};
