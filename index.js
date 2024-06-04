const {createClient} = require('redis');
const jwt = require("jsonwebtoken");
const crypto = require('crypto');
const nodeJwtRedisError = require("./nodeJwtRedisError");
class RedisJwtService {
    constructor(redis,jwt) {
        this.redisInit(redis);
        this.jwtInit(jwt);
        this.secretKey = 'PpZezRYKmpyyI0TuTy1ojx3C6L+czAA='
        this.saltKey = 'b6a5a19482bbf3de41298394278348839c6a7c9a52cef0a8e9af9fa5499f2a2568b9b7463c41f668bd0db507289b085cb93aee2bfb959be18ee5ea781c868971'
    }
    redisInit = async(redis)=>{
        //* Redis 연결
        if(!!redis&&Object.keys(redis).length>0){
            const redisClient = createClient(redis);
            redisClient.on('connect', () => {
                console.log('✌️ Redis connected!');
            });
            redisClient.on('error', (err) => {
                throw new nodeJwtRedisError("Redis", "ConnectionError", 400, 300, err.message);
            });
            redisClient.connect().then(); // redis v4 연결 (비동기)
            this.redis = redisClient;
            this.redisAsync = redisClient.v4;// 기본 redisClient 객체는 콜백기반인데 v4버젼은 프로미스 기반이라 사용
        }else{
            const redisClient = createClient({ legacyMode: true });
            redisClient.on('connect', () => {
                console.log('✌️ Redis connected!');
            });
            redisClient.on('error', (err) => {
                throw new nodeJwtRedisError("Redis", "ConnectionError", 400, 300, err.message);
            });
            redisClient.connect().then(); // redis v4 연결 (비동기)
            this.redis = redisClient;
            this.redisAsync = redisClient.v4;// 기본 redisClient 객체는 콜백기반인데 v4버젼은 프로미스 기반이라 사용
        }
    }
    jwtInit = async(jwtConfig)=>{
        //* jwt 셋팅
        this.jwt = jwt;
        if(!!jwt&&Object.keys(jwtConfig).length>0){
            this.jwtAccessSecret = jwtConfig.accessSecret;
            this.jwtRefreshSecret = jwtConfig.refreshSecret;
            this.jwtAccessExpiresIn = jwtConfig.accessExpiresIn;
            this.jwtRefreshExpiresIn = jwtConfig.refreshExpiresIn;
        }else{
            throw new nodeJwtRedisError("Jwt", "ValidationError", 400, 310, 'There is no environment variables for JWT');
        }
    }
    /**
     * AES 암호화
     */
    aesEnc = (text) => {
        let iv = crypto.randomBytes(16);
        let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(this.secretKey), iv);
        let encrypted = cipher.update(text);
    
        encrypted = Buffer.concat([encrypted, cipher.final()]);
    
        return iv.toString('hex') + this.saltKey + encrypted.toString('hex');
    }
    /**
     * AES 복호화
     */
    aesDec = (encstr) => {
        let textParts = encstr.split(this.saltKey);
        let iv = Buffer.from(textParts.shift(), 'hex');
        let encryptedText = Buffer.from(textParts.join(this.saltKey), 'hex');
        let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(this.secretKey), iv);
        let decrypted = decipher.update(encryptedText);
        
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString();
    }

    /**
     * issueSoleToken
     */
    issueSoleToken = async (keyId) => {
        keyId = keyId.toString()
        const data = await this.redisAsync.get(keyId); // 등록된 soleToken 있는지 확인
        if(!!data){
            throw new nodeJwtRedisError("Jwt","issueSoleTokenError",400, 320, 'There are already issued tokens!');
        }else{
            let soleTokenOptions = {}
            if(!!this.jwtAccessExpiresIn && this.jwtAccessExpiresIn>0){
                soleTokenOptions = {
                    expiresIn: this.jwtAccessExpiresIn,
                    subject : 'soleToken'
                }
            }else{
                soleTokenOptions = {
                    subject : 'soleToken'
                }
            }
            const soleToken = jwt.sign({keyId: this.aesEnc(keyId)} , this.jwtAccessSecret, soleTokenOptions);
            if (!!this.jwtAccessExpiresIn && this.jwtAccessExpiresIn>0) {
                this.redis.set(keyId, soleToken,'EX', this.jwtAccessExpiresIn ,async () => {
                    console.log(keyId + ' : soleToken regist complete')
                })
            } else {
                this.redis.set(keyId, soleToken ,async () => {
                    console.log(keyId + ' : soleToken regist complete(unlimit)')
                })
            }
            return { 
                soleToken : soleToken
            }
        }
    }
    /**
     * reissueSoleToken
     */
    reissueSoleToken = async (soleToken, keyId) => {
        if(!!soleToken){
            const soleTokenVerifyResult = await this.verifySoleToken(soleToken, keyId, 'offError');
            if (soleTokenVerifyResult.ok === false && soleTokenVerifyResult.message === 'jwt expired') {
                let soleTokenOptions = {}
                if(!!this.jwtAccessExpiresIn && this.jwtAccessExpiresIn>0){
                    soleTokenOptions = {
                        expiresIn: this.jwtAccessExpiresIn,
                        subject : 'soleToken'
                    }
                }else{
                    soleTokenOptions = {
                        subject : 'soleToken'
                    }
                }
                const soleToken = jwt.sign({keyId: this.aesEnc(keyId)} , this.jwtAccessSecret, soleTokenOptions);
                if (!!this.jwtAccessExpiresIn && this.jwtAccessExpiresIn>0) {
                    this.redis.set(keyId, soleToken,'EX', this.jwtAccessExpiresIn ,async () => {
                        console.log(keyId + ' : soleToken regist complete')
                    })
                } else {
                    this.redis.set(keyId, soleToken ,async () => {
                        console.log(keyId + ' : soleToken regist complete(unlimit)')
                    })
                }
                return { 
                    soleToken : soleToken
                }            
            }else if (soleTokenVerifyResult.ok === false) {
                throw new nodeJwtRedisError("Jwt","TokenInvaildError",401, 334,`No authorized soleToken!: ${soleTokenVerifyResult.message}`);
            }else if (soleTokenVerifyResult.ok === true) {
                throw new nodeJwtRedisError("Jwt","TokenExpiredError",401,340, 'SoleToken is not expired!');
            }
        }else{
            throw new nodeJwtRedisError("Jwt","ValidationError",400, 311,'soleToken are required!');
        }
    }
    /**
     * verifySoleToken
     */
    verifySoleToken = async (token, keyId, mode) => { // sole token 검증
        token = token.toString();
        keyId = keyId.toString();
        let decoded = null;
        try {
          const data = await this.redisAsync.get(keyId); // sole token 가져오기
          if (token === data) {
            decoded = jwt.verify(token, this.jwtAccessSecret);
            decoded.ok = true;
            decoded.message = 'valid'
            decoded.keyId = this.aesDec(decoded.keyId)
            return decoded;
          } else {
            return {
                ok: false,
                message: 'unauthorized',
                keyId: this.aesDec(jwt.decode(token).keyId)
            };
          }
        } catch (err) {
            if(mode=='offError'){
                return {
                    ok: false,
                    message: err.message,
                    keyId: this.aesDec(jwt.decode(token).keyId)
                };
            }else{
                if(err.name =='TokenExpiredError'){
                    throw new nodeJwtRedisError("Jwt","TokenExpiredError",401,342, 'Sole token is expired!');
                }else if(err.name =='JsonWebTokenError'){
                    throw new nodeJwtRedisError("Jwt","TokenInvaildError",401, 332, err.message);
                }else{
                    throw new nodeJwtRedisError("Jwt", err.name, 400, 350, err);
                }
            }
        }
    }
    /**
     * issueTokenPair
     */
    issueTokenPair = async (keyId) => {
        keyId = keyId.toString()
        const data = await this.redisAsync.get(keyId); // 등록된 refreshToken이 있는지 확인
        if(!!data){
            throw new nodeJwtRedisError("Jwt","issueTokenPairError",400, 320, 'There are already issued tokens!');
        }else{
            let accessTokenOptions = {}
            if(!!this.jwtAccessExpiresIn && this.jwtAccessExpiresIn>0){
                accessTokenOptions = {
                    expiresIn: this.jwtAccessExpiresIn,
                    subject : 'accessToken'
                }
            }else{
                accessTokenOptions = {
                    subject : 'accessToken'
                }
            }
            let refreshTokenOptions = {}
            if(!!this.jwtRefreshExpiresIn && this.jwtRefreshExpiresIn>0){
                refreshTokenOptions = {
                    expiresIn: this.jwtRefreshExpiresIn,
                    subject : 'refreshToken'
                }
            }else{
                refreshTokenOptions = {
                    subject : 'refreshToken'
                }
            }
            const accessToken = jwt.sign({keyId: this.aesEnc(keyId)} , this.jwtAccessSecret, accessTokenOptions);
            const refreshToken = jwt.sign({keyId: this.aesEnc(keyId)} , this.jwtRefreshSecret, refreshTokenOptions);
            if (!!this.jwtRefreshExpiresIn && this.jwtRefreshExpiresIn>0) {
                this.redis.set(keyId, refreshToken,'EX', this.jwtRefreshExpiresIn ,async () => {
                    console.log(keyId + ' : refreshToken regist complete')
                })
            } else {
                this.redis.set(keyId, refreshToken ,async () => {
                    console.log(keyId + ' : refreshToken regist complete(unlimit)')
                })
            }
            return { 
                accessToken : accessToken,
                refreshToken : refreshToken
            }
        }
    }

    /**
     * reissueAccessToken
     */
     reissueAccessToken = async (accessToken,refreshToken) => {
        if(!!accessToken&&!!refreshToken){
            const verifyResult = await this.verifyAccessToken(accessToken,'offError');
            const keyId = verifyResult.keyId;
            const refreshVerifyResult = await this.verifyRefreshToken(refreshToken, keyId,'offError');
            if(refreshVerifyResult.ok==true){
                if (verifyResult.ok === true||(verifyResult.ok === false && verifyResult.message === 'jwt expired')) {
                    if (verifyResult.ok === true) {
                        await this.destroyAccessToken(accessToken)
                    }
                    let accessTokenOptions = {}
                    if(!!this.jwtAccessExpiresIn && this.jwtAccessExpiresIn>0){
                        accessTokenOptions = {
                            expiresIn: this.jwtAccessExpiresIn,
                            subject : 'accessToken'
                        }
                    }else{
                        accessTokenOptions = {
                            subject : 'accessToken'
                        }
                    }
                    let refreshTokenOptions = {}
                    if(!!this.jwtRefreshExpiresIn && this.jwtRefreshExpiresIn>0){
                        refreshTokenOptions = {
                            expiresIn: this.jwtRefreshExpiresIn,
                            subject : 'refreshToken'
                        }
                    }else{
                        refreshTokenOptions = {
                            subject : 'refreshToken'
                        }
                    }
                    const newAccessToken = jwt.sign({keyId:this.aesEnc(keyId)}, this.jwtAccessSecret, accessTokenOptions);
                    const newRefreshToken = jwt.sign({keyId: this.aesEnc(keyId)} , this.jwtRefreshSecret, refreshTokenOptions);
                    if (!!this.jwtRefreshExpiresIn && this.jwtRefreshExpiresIn>0) {
                        this.redis.set(keyId, newRefreshToken,'EX', this.jwtRefreshExpiresIn ,async () => {
                            console.log(keyId + ' : refreshToken regist complete')
                        })
                    } else {
                        this.redis.set(keyId, newRefreshToken ,async () => {
                            console.log(keyId + ' : refreshToken regist complete(unlimit)')
                        })
                    }
                    return { 
                        accessToken : newAccessToken,
                        refreshToken : newRefreshToken
                    }
                }else if (verifyResult.ok === false) {
                    throw new nodeJwtRedisError("Jwt","TokenInvaildError",401,333,`No authorized accessToken!: ${verifyResult.message}`);
                }
            }else if (refreshVerifyResult.ok === false) {
                throw new nodeJwtRedisError("Jwt","TokenInvaildError",401, 334,`No authorized refreshToken!: ${refreshVerifyResult.message}`);
            }
        }else{
            throw new nodeJwtRedisError("Jwt","ValidationError",400, 311,'Both an access token and a refresh token are required!');
        }
    }

    /**
     * verifyAccessToken
     */
     verifyAccessToken = async (token,mode) => { // access token 검증
        token = token.toString();
        let decoded = null;
        try {
          const data = await this.redisAsync.get(token); // access token 가져오기
          if(data=="logout"){
            return {
                ok: false,
                message: 'destroyed'
            };
          }else{
              decoded = jwt.verify(token, this.jwtAccessSecret);
              decoded.ok = true;
              decoded.message = 'valid'
              decoded.keyId = this.aesDec(decoded.keyId)
              return decoded;
          }
        } catch (err) {
            if(mode=='offError'){
                return {
                    ok: false,
                    message: err.message,
                    keyId: this.aesDec(jwt.decode(token).keyId)
                };
            }else{
                if(err.name =='TokenExpiredError'){
                    throw new nodeJwtRedisError("Jwt","TokenExpiredError",401, 341,'Access token is expired!');
                }else if(err.name =='JsonWebTokenError'){
                    throw new nodeJwtRedisError("Jwt","TokenInvaildError",401, 331, err.message);
                }else{
                    throw new nodeJwtRedisError("Jwt",err.name,400,350,err);
                }
            }
        }
    }
    /**
     * verifyRefreshToken
     */
     verifyRefreshToken = async (token, keyId, mode) => { // refresh token 검증
        keyId = keyId.toString();
        token = token.toString();
        let decoded = null;
        try {
          const data = await this.redisAsync.get(keyId); // refresh token 가져오기
          if (token === data) {
            decoded = jwt.verify(token, this.jwtRefreshSecret);
            decoded.ok = true;
            decoded.message = 'valid'
            decoded.keyId = this.aesDec(decoded.keyId)
            return decoded;
          } else {
            return {
                ok: false,
                message: 'unauthorized',
                keyId: this.aesDec(jwt.decode(token).keyId)
            };
          }
        } catch (err) {
            if(mode=='offError'){
                return {
                    ok: false,
                    message: err.message,
                    keyId: this.aesDec(jwt.decode(token).keyId)
                };
            }else{
                if(err.name =='TokenExpiredError'){
                    throw new nodeJwtRedisError("Jwt","TokenExpiredError",401,342, 'Refresh token is expired!');
                }else if(err.name =='JsonWebTokenError'){
                    throw new nodeJwtRedisError("Jwt","TokenInvaildError",401, 332, err.message);
                }else{
                    throw new nodeJwtRedisError("Jwt", err.name, 400, 350, err);
                }
            }
        }
      }
    /**
     * destroyToken
     */
     destroyToken = async (accessToken,refreshToken) => {
        if(!!accessToken,!!refreshToken){
            const verifyResult = await this.verifyAccessToken(accessToken,'offError');
            const refreshVerifyResult = await this.verifyRefreshToken(refreshToken, verifyResult.keyId,'offError');
            if(refreshVerifyResult.ok==true){
                if (verifyResult.ok) {
                    await this.redisAsync.del(verifyResult.keyId);
                    const currentTime = Math.round((new Date().getTime())/1000);
                    const restExipreTime = verifyResult.exp-currentTime
  
                    if(restExipreTime>3){
                        this.redis.set(accessToken, 'logout','EX', restExipreTime ,async () => {
                            console.log(accessToken + ' : blackList regist complete')
                        })
                    }
                }else if (verifyResult.ok === false && verifyResult.message === 'jwt expired') {
                    console.error('AccessToken is expired!')
                }else if (verifyResult.ok === false) {
                    throw new nodeJwtRedisError("Jwt","TokenInvaildError",401,333,`No authorized accessToken!: ${verifyResult.message}`);
                }
            }else if(refreshVerifyResult.ok === false&& refreshVerifyResult.message === 'jwt expired'){
                console.error('refreshToken is expired!')
            }else if(refreshVerifyResult.ok === false){
                throw new nodeJwtRedisError("Jwt","TokenInvaildError",401,334,`No authorized refreshToken!: ${refreshVerifyResult.message}`);
            }

        }else{
            throw new nodeJwtRedisError("Jwt","ValidationError",400,311,'Both an access token and a refresh token are required!');
        }
    }
    /**
     * destroyAccessToken
     */
     destroyAccessToken = async (accessToken) => {
        if(!!accessToken){
            const verifyResult = await this.verifyAccessToken(accessToken,'offError');
            if (verifyResult.ok) {
                await this.redisAsync.del(verifyResult.keyId);
                const currentTime = Math.round((new Date().getTime())/1000);
                const restExipreTime = verifyResult.exp-currentTime
                
                if(restExipreTime>3){
                    this.redis.set(accessToken, 'logout','EX', restExipreTime ,async () => {
                        console.log(accessToken + ' : blackList regist complete')
                    })
                }
            }else if (verifyResult.ok === false && verifyResult.message === 'jwt expired') {
                console.error('AccessToken is expired!')
            }else if (verifyResult.ok === false) {
                throw new nodeJwtRedisError("Jwt","TokenInvaildError",401,333,`No authorized accessToken!: ${verifyResult.message}`);
            }
        }else{
            throw new nodeJwtRedisError("Jwt","ValidationError",400,311,'access token is required!');
        }
    }
}
module.exports.jwtRedis = RedisJwtService;
module.exports.error = nodeJwtRedisError;