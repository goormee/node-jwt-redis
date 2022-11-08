# Node-jwt-redis

## Features

- Json Web Token method is used, but forced logout function can be used.
- There is extensibility by using Json Web Token method.
- There is security like the Session method.

## Tech

Node-jwt-redis uses a number of open source projects to work properly:

- [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken)
- [redis](https://www.npmjs.com/package/redis)

And of course `Node-jwt-redis` itself is open source with a [public repository](https://github.com/goormee/node-jwt-redis)
 on GitHub.

## Installation

Here's how to install it:
```bash
npm install node-jwt-redis
```
> Note: 
If `jsonwebtoken` and `redis` are already installed, there is a possibility of conflict.
So you better to delete it in advance

## Usage
#### Basic Example
```cpp
const jwtRedis = require("node-jwt-redis");
const redisOptions = {
   socket: {
       host: 'localhost',
       port: Number(6379)
   },
   password: 'redisPassword',
   legacyMode: true // essential
};
const jwtOptions = {
    accessSecret : Config.accessSecret, // secret string
    refreshSecret:  Config.refreshSecret, // secret string
    accessExpiresIn:  60*15, // seconds
    refreshExpiresIn:  60*60*24*90 // seconds
}
const jwtr = new jwtRedis(redisOptions,jwtOptions);

//issue accessToken and refreshToken
let {accessToken,refreshToken} = await jwtr.issueTokenPair(keyId);
//reissue accessToken
    {accessToken,refreshToken} = await jwtr.reissueAccessToken(accessToken,refreshToken);
//verify accessToken => Commonly used as middleware
const {ok, message, id, exp, ...} = await jwtr.verifyAccessToken(accessToken);
/*{
    ok: boolean ,
    message: message,
    id : keyId,
    exp : expire time,
    ...
}*/

//verify refreshToken
const boolean = await jwtr.verifyRefreshToken(refreshToken,keyId);

//destroy accessToken and refreshToken => Used when logging out
await jwtr.destroyToken(accessToken,refreshToken);
```

## API


#### Method for creating a token.
```cpp
jwtr.issueTokenPair(keyId): Promise
```
#### Method for recreating an accessToken.
```cpp
jwtr.reissueAccessToken(accessToken,refreshToken): Promise
```
#### Method for verifying an accessToken
```cpp
jwtr.verifyAccessToken(accessToken): Promise
```
#### Method for verifying a refreshToken
```cpp
jwtr.verifyRefreshToken(refreshToken,keyId): Promise
```
#### Method for breaking tokens
```cpp
jwtr.destroyToken(accessToken,refreshToken): void
```
#### ETC Redis Method
```cpp
jwtr.redisAsync.set(key,value) : Promise
jwtr.redis.set(key,value,callbackFunc) 
...
jwtr.redis.quit()
```
> You can use the general method of redis\
ex) jwtr.redis.[method]

#### ETC Jsonwebtoken Method
```cpp
jwtr.jwt.decode(token [, options])
```
> You can use the general method of jsonwebtoken\
ex) jwtr.jwt.[method]

## License

ISC
