const {createClient} = require('redis');
const jwt = require("jsonwebtoken");
class RedisJwtService {
    constructor(redis,jwt) {
        //* Redis 연결
        if(!!redis&&Object.keys(redis).length>0){
            const redisClient = createClient({ url: redis.url });
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
    issueTokenPair = async (id) => {
        const data = await this.redisAsync.get(id); // 등록된 refreshToken이 있는지 확인
        if(!!data){
            throw new Error('issueTokenPair Error : There are already issued tokens!');
        }else{
            const accessToken = jwt.sign({id} , this.jwtAccessSecret, {
                expiresIn: this.jwtAccessExpiresIn,
                subject : 'accessToken'
            });
            const refreshToken = jwt.sign({id} , this.jwtRefreshSecret, {
                expiresIn: this.jwtRefreshExpiresIn,
                subject : 'refreshToken'
            });
            this.redis.set(id, refreshToken,'EX', this.jwtRefreshExpiresIn ,async () => {
                console.log(id + ' : refreshToken regist complete')
            })
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
        if(!!accessToken,!!refreshToken){
            const verifyResult = await this.verifyAccessToken(accessToken);
            const decoded = jwt.decode(accessToken)
            if (decoded === null) {
                throw new Error('reissueAccessToken Error : No authorized!')
            }
            const userId = decoded.id;
            const refreshVerifyResult = await this.verifyRefreshToken(refreshToken, userId);

            if(refreshVerifyResult){
                if (verifyResult.ok === false && verifyResult.message === 'jwt expired') {
                    const accessToken = jwt.sign({userId}, this.jwtAccessSecret, {
                        expiresIn: this.jwtAccessExpiresIn,
                        subject : 'accessToken'
                    });
                    return { 
                        accessToken : accessToken,
                        refreshToken : refreshToken
                    }
                }else{
                    throw new Error('reissueAccessToken Error : Access token is not expired!')
                }
            }else{
                throw new Error('reissueAccessToken Error : No authorized!')
            }

        }else{
            throw new Error('reissueAccessToken Error : Access token and refresh token are need for reissue!')
        }
    }
    /**
     * verifyAccessToken
     */
     verifyAccessToken = async (token) => { // access token 검증
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
            throw new Error(err)
        }
    }
    /**
     * verifyRefreshToken
     */
     verifyRefreshToken = async (token, userId) => { // refresh token 검증

        try {
          const data = await this.redisAsync.get(userId); // refresh token 가져오기
          if (token === data) {
            try {
              jwt.verify(token, this.jwtRefreshSecret);
              return true;
            } catch (err) {
                throw new Error(err)
            }
          } else {
            return false;
          }
        } catch (err) {
            throw new Error(err)
        }
      }
    /**
     * destroyToken
     */
     destroyToken = async (accessToken,refreshToken) => {
        if(!!accessToken,!!refreshToken){
            const verifyResult = await this.verifyAccessToken(accessToken);
            const decoded = jwt.decode(accessToken)
            if (decoded === null) {
                throw new Error('destroyToken Error : No authorized!')
            }
            const refreshVerifyResult = await this.verifyRefreshToken(refreshToken, decoded.id);
            if(refreshVerifyResult){
                if (verifyResult.ok) {
                    await this.redisAsync.del(decoded.id);
                    const currentTime = Math.round((new Date().getTime())/1000);
                    const restExipreTime = decoded.exp-currentTime
  
                    if(restExipreTime>10){
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