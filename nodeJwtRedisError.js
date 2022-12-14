class nodeJwtRedisError extends Error {
    constructor(type = 'GENERIC', name = 'GENERIC ERROR', status = 400, code=200, ...params) {
        super(...params)
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, nodeJwtRedisError)
        }
        
        this.type = type
        this.name = name
        this.status = status
        this.code = code
    }
}
module.exports = nodeJwtRedisError;