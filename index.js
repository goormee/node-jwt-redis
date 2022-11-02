const {createClient} = require('redis');
const jwt = require("jsonwebtoken");
class RedisJwtService {
    constructor(redis,jwt) {
        //* Redis 연결
        if(!!redis){
            const redisClient = createClient({ url: redis.url });
            redisClient.on('connect', () => {
                console.log('✌️ Redis connected!');
            });
            redisClient.on('error', (err) => {
                console.error('Redis Client Error : ', err);
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
                console.error('Redis Client Error : ', err);
            });
            redisClient.connect().then(); // redis v4 연결 (비동기)
            this.redis = redisClient;
            this.redisAsync = redisClient.v4;// 기본 redisClient 객체는 콜백기반인데 v4버젼은 프로미스 기반이라 사용
        }
        if(!!jwt){
            this.jwtAccessSecret = jwt.accessSecret;
            this.jwtRefreshSecret = jwt.refreshSecret;
            this.jwtAccessExpiresIn = jwt.accessExpiresIn;
            this.jwtRefreshExpiresIn = jwt.refreshExpiresIn;
        }else{
            console.error('Jwt Env Error : ', 'There is no environment variables for JWT');
        }
    }
    /**
     * issueTokenPair
     */
    issueTokenPair = (id) => {
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
    /**
     * reissueAccessToken
     */
     reissueAccessToken = async (accessToken,refreshToken) => {
        if(!!accessToken,!!refreshToken){
            const verifyResult = await this.verifyAccessToken(accessToken);
            const decoded = jwt.decode(accessToken)
            if (decoded === null) {
                console.error('reissueAccessToken Error : ','No authorized!')
                return false;
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
                    console.error('reissueAccessToken Error : ','Access token is not expired!')
                    return false;
                }
            }else{
                console.error('reissueAccessToken Error : ','No authorized!')
                return false;
            }

        }else{
            console.error('reissueAccessToken Error : ','Access token and refresh token are need for reissue!')
            return false;
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
          return {
            ok: false,
            message: err.message,
          };
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
              return false;
            }
          } else {
            return false;
          }
        } catch (err) {
          return false;
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
                console.error('destroyToken Error : ','No authorized!')
                return false;
            }
            const refreshVerifyResult = await this.verifyRefreshToken(refreshToken, decoded.id);
            if(refreshVerifyResult){
                if (verifyResult.ok) {
                    await this.redisAsync.del(decoded.id);
                    const currentTime = Math.round((new Date().getTime())/1000);
                    const restExipreTime = decoded.exp-currentTime
  
                    if(restExipreTime>1){
                        this.redis.set(accessToken, 'logout','EX', restExipreTime ,async () => {
                            console.log(accessToken + ' : blackList regist complete')
                        })
                    }
                }else{
                    console.error('destroyToken Error : ','Access token is expired!')
                    return false;
                }
            }else{
                console.error('destroyToken Error : ','No authorized!')
                return false;
            }

        }else{
            console.error('reissueAccessToken Error : ','Access token and refresh token are need for reissue!')
            return false;
        }
    }
}
module.exports = RedisJwtService;