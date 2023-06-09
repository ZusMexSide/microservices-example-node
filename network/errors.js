const response = require('./response')

function errors( err, req, res, next) {
    console.error('[Error]', err)

    const message = err.message
    const status = err.statusCode || 500
    response.error( req, res, message, status )
}

module.exports = errors