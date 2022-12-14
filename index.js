const {createClient} = require('redis');
const jwt = require("jsonwebtoken");
class RedisJwtService {
    constructor(redis,jwt) {
        this.redisInit(redis);
        this.jwtInit(jwt);
    }
    redisInit = async(redis)=>{
        //* Redis 연결
        if(!!redis&&Object.keys(redis).length>0){
            const redisClient = createClient(redis);
            redisClient.on('connect', () => {
                console.log('✌️ Redis connected!');
            });
            redisClient.on('error', (err) => {
                throw new Error(err);
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
                throw new Error(err);
            });
            redisClient.connect().then(); // redis v4 연결 (비동기)
            this.redis = redisClient;
            this.redisAsync = redisClient.v4;// 기본 redisClient 객체는 콜백기반인데 v4버젼은 프로미스 기반이라 사용
        }
    }
    jwtInit = async(jwt)=>{
        //* jwt 셋팅
        this.jwt = jwt;
        if(!!jwt&&Object.keys(jwt).length>0){
            this.jwtAccessSecret = jwt.accessSecret;
            this.jwtRefreshSecret = jwt.refreshSecret;
            this.jwtAccessExpiresIn = jwt.accessExpiresIn;
            this.jwtRefreshExpiresIn = jwt.refreshExpiresIn;
        }else{
            throw new Error('JWT ERROR : There is no environment variables for JWT');
        }
    }    
    /**
     * issueTokenPair
     */
    issueTokenPair = async (keyId) => {
        keyId = keyId.toString()
        const data = await this.redisAsync.get(keyId); // 등록된 refreshToken이 있는지 확인
        if(!!data){
            throw new Error('issueTokenPair Error : There are already issued tokens!');
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
            const accessToken = jwt.sign({keyId} , this.jwtAccessSecret, accessTokenOptions);
            const refreshToken = jwt.sign({keyId} , this.jwtRefreshSecret, refreshTokenOptions);
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
            const decoded = jwt.decode(accessToken)
            if (decoded === null) {
                throw new Error('reissueAccessToken Error : No authorized accessToken!')
            }
            const keyId = decoded.keyId;
            const refreshVerifyResult = await this.verifyRefreshToken(refreshToken, keyId,'offError');
            if(refreshVerifyResult){
                if (verifyResult.ok === false && verifyResult.message === 'jwt expired') {
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
                    const accessToken = jwt.sign({keyId}, this.jwtAccessSecret, accessTokenOptions);
                    return { 
                        accessToken : accessToken,
                        refreshToken : refreshToken
                    }
                }else{
                    throw new Error('reissueAccessToken Error : Access token is not expired!')
                }
            }else{
                throw new Error('reissueAccessToken Error : No authorized refreshToken!')
            }
        }else{
            throw new Error('reissueAccessToken Error : Access token and refresh token are need for reissue!')
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
              return decoded;
          }
        } catch (err) {
            if(mode=='offError'){
                return {
                    ok: false,
                    message: err.message
                };
            }else{
                throw new Error(err)
            }
        }
    }
    /**
     * verifyRefreshToken
     */
     verifyRefreshToken = async (token, keyId, mode) => { // refresh token 검증
        keyId = keyId.toString();
        try {
          const data = await this.redisAsync.get(keyId); // refresh token 가져오기
          if (token === data) {
            try {
              jwt.verify(token, this.jwtRefreshSecret);
              return true;
            } catch (err) {
                if(mode=='offError'){
                    return false;
                }else{
                    throw new Error(err)
                }
            }
          } else {
            return false;
          }
        } catch (err) {
            if(mode=='offError'){
                return false;
            }else{
                throw new Error(err)
            }
        }
      }
    /**
     * destroyToken
     */
     destroyToken = async (accessToken,refreshToken) => {
        if(!!accessToken,!!refreshToken){
            const verifyResult = await this.verifyAccessToken(accessToken,'offError');
            const decoded = jwt.decode(accessToken)
            if (decoded === null) {
                throw new Error('destroyToken Error : No authorized!')
            }
            const refreshVerifyResult = await this.verifyRefreshToken(refreshToken, decoded.keyId,'offError');
            if(refreshVerifyResult){
                if (verifyResult.ok) {
                    await this.redisAsync.del(decoded.keyId);
                    const currentTime = Math.round((new Date().getTime())/1000);
                    const restExipreTime = decoded.exp-currentTime
  
                    if(restExipreTime>3){
                        this.redis.set(accessToken, 'logout','EX', restExipreTime ,async () => {
                            console.log(accessToken + ' : blackList regist complete')
                        })
                    }
                }else{
                    throw new Error('destroyToken Error : Access token is expired!')
                }
            }else{
                throw new Error('destroyToken Error : No authorized!')
            }

        }else{
            throw new Error('destroyToken Error : Access token and refresh token are need for reissue!')
        }
    }
}
module.exports = RedisJwtService;