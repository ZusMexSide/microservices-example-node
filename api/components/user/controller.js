const { nanoid } = require('nanoid')
const auth = require('../auth')

const TABLE = 'user'

module.exports = function( injectedStore ) {
    let store = injectedStore
    if ( !store ) {
        store = require('../../../store/mysql')
    }
    
    function list() {
        return store.list(TABLE)
    }

    function get(id) {
        return store.get(TABLE, id)
    }

    async function upsert( body ) {
        const user = {
            name: body.name,
            username: body.username
        }
        user.id = ( body.id ) ? body.id : nanoid()

        if ( body.password  || body.username ) {
            await auth.upsert({
                id: user.id,
                username: user.username,
                password: body.password,
            })
        }
        return store.upsert(TABLE, user) 
    }

    function follow( from, to ) {
        return store.upsert( `${TABLE}_follow`, {
            user_from: from,
            user_to: to,
        })
    }

    async function following( user ) {
        const join = {}
        join[ TABLE ] = 'user_to'
        const query = { user_from: user }
		
		return await store.query( `${TABLE}_follow`, query, join );
	}

    return {
        list,
        get,
        upsert,
        follow,
        following
    }
}