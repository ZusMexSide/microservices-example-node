const bcrypt = require('bcrypt');
const auth = require('../../../auth')
const error = require('../../../utils/error')
const TABLE = 'auth'

module.exports = function( injectedStore ) {
    let store = injectedStore
    if ( !store ) {
        store = require('../../../store/mysql')
    }

    async function login( username, password ) {
        const data  = await store.query( TABLE, { username: username } )
        if ( !data ) throw error('Invalid data', 400)
        return bcrypt.compare( password, data.password )
            .then( equal => {
                if ( equal ) {
                    return auth.sign({ ...data })
                } else {
                    throw error('Invalid data', 400)
                }
            })
    }

    async function upsert( data ) {
        const authData = {
            id: data.id,
        }

        if ( data.username ) {
            authData.username = data.username
        }

        if ( data.password ) { 
            authData.password = await bcrypt.hash(data.password, 5)
        }

        return store.upsert( TABLE, authData )
    }

    return {
        upsert,
        login
    }
}