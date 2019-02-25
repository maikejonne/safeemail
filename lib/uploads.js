"use strict";

var express = require('express'),
    router = express.Router(),
    fs = require('fs'),
    nconf = require('nconf'),
    utils = require('../../public/src/utils'),
    crypto = require('crypto'),
    createHash = require('create-hash'),
    ecc = require('tiny-secp256k1'),
    secp256k1 = require('secp256k1'),
    markdown = require("markdown").markdown,
    multipart = require('connect-multiparty'),
    multipartMiddleware = multipart(),
    mymongodb = require('./mymongodb'),
    xxtea = require('./xxtea'),
    MAX_LIMIT_NOTICE_LENGTH = 1024,
    MAX_LIMIT_MESSAGE_LENGTH = 8192,
    MAX_LIMIT_LEAVEMSG_COUNT = 50;


function isArray(object){
    return object && typeof object==='object' &&
        Array === object.constructor;
}

function tryConToJson(strObj) {
    try {
        return JSON.parse(strObj);
    } catch (e) {
        return null;
    }
}

function RandString(length) {
    var strRandKey = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var maxPos = strRandKey.length;
    var strRet = '';
    for (var i = 0; i < length; i++) {
        strRet += strRandKey.charAt(Math.floor(Math.random() * maxPos));
    }
    return strRet;
}

function verify(message, pubBuffer, signature) {
    try {
        var hash = createHash('sha256').update(Buffer.from(message)).digest();

        return secp256k1.verify(hash,
            secp256k1.signatureImport(Buffer.from(signature, 'base64').slice(0, -1)),
            pubBuffer);
    } catch (e) {
        return false;
    }
}

function doDealAttachment(sourcefilename, distFilename,  srchash, srcsize, password, callback){
    var nDestLen = srcsize;
    var destHash = srchash;
    //if(srcsize>1024000){
    //    callback(null, {"encrypt":0, "dlhash":destHash, "dllen":nDestLen});
    //}else{
        var rs = fs.createReadStream(sourcefilename);
        var dest = fs.createWriteStream(distFilename);
        var md5sum = crypto.createHash('md5');
        nDestLen = 0;
        rs.on('data', function (chunk) {
            rs.pause();
            var encdata = xxtea.encrypt(chunk,password);
            var buf = Buffer.allocUnsafe(4);
            buf.writeUInt32LE(encdata.length, 0);
            buf = Buffer.concat([buf, encdata]);
            md5sum.update(buf);
            nDestLen = nDestLen+encdata.length+4;
            dest.write(buf);
            rs.resume();
        });
        rs.on('end', function () {
            destHash = md5sum.digest('hex').toLowerCase();

            dest.end();
            callback(null, {"encrypt":1, "dlhash":destHash, "dllen":nDestLen});
        });
        rs.on('error', function () {
            fs.unlinkSync(distFilename);
            callback({"message":"read source error."});
        });
    //}
}

/**
 * @api {post} /session 01.Request New Session
 * @apiName session
 * @apiGroup SeMail
 * @apiDescription 服务提供商无法预知来访者信息，来访者每次访问时，在session中随机生成32个字符的KEY，让用户对该KEY进行签名。服务提供商可以通过正确的签名来判别用户的合法性。为了避免session被拦截滥用，RandKey每次使用后即可作废。
 * 
 * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "session": "alskdjeualskdjeualskdjeualskdjeu"
 *     }
 */
router.post('/session', function (req, res) {
    req.session.randkey = RandString(32);
    res.send({"session": req.session.randkey});
});


/**
 * @api {post} /reg 02.Regist New User
 * @apiName reg
 * @apiGroup SeMail
 * @apiDescription 注册新的用户。<br>这是一个可选的接口。服务提供商可根据需求，自行提供有更多需求的注册。
 * 
 * @apiParam {String} username 基于ECC生成的压缩公钥(33字节)。
 * @apiParam {String} signature Signature 预注册用户对Base64.encode(session-randkey)字符串的签名。
 * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "register": "ok"
 *     }
 *  @apiError 400 Bad Request 
 */
router.post('/reg', function (req, res) {
    if (!req.body || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 || typeof(req.body.username) !== 'string' || req.body.username.length !== 44 ||
        typeof(req.body.signature) !== 'string') {
        return res.sendStatus(400);
    }
    var _pubkey = Buffer.from(req.body.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }
    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    var hName = _pubkey.toString('hex');
    mymongodb.getUidByUsername(hName, function (err, exist) {
        if (err) {
            return res.sendStatus(400);
        }
        if (exist) {
            return res.sendStatus(400);
        } else {
            var _ipaddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
            mymongodb.createNewUser(hName, _ipaddress, function (err) {
                if (err) {
                    return res.sendStatus(400);
                }
                res.send({"register": "ok"});
            });            
        }
    });
});


/**
 * @api {post} /tempauth 03.Generate temp auth
 * @apiName tempauth
 * @apiGroup SeMail
 * @apiDescription 持有凭证的某人回复用户发起的授权，这里的某人是未知的。凡持有用户授权凭证的，都可以给该用户回复，回复信息长度被限制在1024个字节。
 *
 * @apiParam {String} name 回复给哪个用户的公钥
 * @apiParam {String} data 回复的信息内容 
 * @apiParam {String} signature 可回复的授权凭证
 * @apiParam {Number} tid 用户提供授权的id号
 * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "ret": 1
 *     }
 *  @apiError 400 Bad Request 
 */
router.post('/tempauth', function (req, res) {
    if (!req.body || typeof(req.body.name) !== 'string' || req.body.name.length !== 44 ||
        typeof(req.body.signature) !== 'string' || typeof(req.body.data) !== 'string' ||
        req.body.data.length > MAX_LIMIT_NOTICE_LENGTH || req.body.data.length <= 0 ||
        typeof(req.body.tid) !== 'number' || !utils.isNumber(req.body.tid, 10) || req.body.tid <= 0) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.name, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }

    var _hName = _pubkey.toString('hex');
    mymongodb.queryTemporaryAuthByIDAndName(req.body.tid, _hName, function(err, result){
        if(err){
            return res.sendStatus(400);
        }
        if(typeof(result.content) !== 'string'){
            return res.sendStatus(400);
        }

        if (verify(Buffer.from(result.content, 'base64').toString(), _pubkey, req.body.signature) === false) {
            return res.sendStatus(400);
        }
        mymongodb.updateTemporaryAuthByID(req.body.tid, req.body.signature, req.body.data, function(err, updateres){
            if(err){
                return res.sendStatus(400);
            }
            if(updateres === 0){
                res.sendStatus(400);
            }else {
                res.send({"ret": updateres});
                var websockets = require.main.require('./src/socket.io');
                if (websockets.server) {
                    websockets.in('sid_' + _hName).emit('semsg', JSON.stringify({
                        'cmd': 'authmsg',
                        'tid': req.body.tid,
                        'data':req.body.data
                    }));
                }
            }
        });
    });
});


/**
 * @api {post} /getnotices 04.Get notices from server
 * @apiName getnotices
 * @apiGroup SeMail
 * @apiDescription 用户在登录/非登录状态下，获取属于自己尚未阅读的通知类消息。
 *
 * @apiParam {String} username 用户的公钥。
 * @apiParam {String} signature 用户对Base64.encode(session-randkey)字符串的签名。
 * @apiParam {Number} timestamp 获取通知的时间标签。
 * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "ts": 1550022966,
 *       "data": [
 *         {
 *           "tid": 128,
 *			 "createdate":150014326,
 *			 "message":"message content"
 *         }
 *       ]
 *     }
 *  @apiError 400 Bad Request 
 */
router.post('/getnotices', function (req, res) {
    if (!req.body || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
        typeof(req.body.username) !== 'string' || req.body.username.length !== 44 ||
        typeof(req.body.signature) !== 'string' ||
        req.body.timestamp === null || !utils.isNumber(req.body.timestamp, 10) || req.body.timestamp < 0) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }
    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    var hName = _pubkey.toString('hex');
    mymongodb.queryTemporaryAuthUnnotices(hName, req.body.timestamp, 15, function(err, results){
        if(err){
            return res.sendStatus(400);
            //return res.send(JSON.stringify({'errmsg': 'refresh data error.'}));
        }

        var retData = {};
        if (results.length < 15) {
            retData.ts = -1;
        } else {
            retData.ts = results[results.length - 1].createdate+86400000;
        }
        retData.data = results;
        res.send(JSON.stringify(retData));
    });
});


/**
 * @api {post} /delnotices 05.Delete notices from server
 * @apiName delnotices
 * @apiGroup SeMail
 * @apiDescription 用户在登录/非登录状态下，删除指定编号的通知类消息。
 * 
 * @apiParam {String} username 用户的公钥。
 * @apiParam {String} signature 用户对Base64.encode(session-randkey)字符串的签名。
 * @apiParam {Array} ids 需删除的通知类消息编号集合。
 * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "ret": 'ok',
 *     }
 *  @apiError 400 Bad Request 
 */
router.post('/delnotices', function (req, res) {
    if (!req.body || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
        typeof(req.body.username) !== 'string' || req.body.username.length !== 44 ||
        typeof(req.body.signature) !== 'string' ||
        req.body.ids === null || !isArray(req.body.ids)) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }
    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    var hName = _pubkey.toString('hex');
    mymongodb.deleteTemporaryAuthNotices(req.body.ids, hName, function(err){
        if(err){
            return res.sendStatus(400);
            //return res.send(JSON.stringify({'errmsg': 'refresh data error.'}));
        }
        res.send(JSON.stringify({'ret': 'ok'}));
    });
});

/*
* @api {post} /getunreads 06.Get Unread Message
* @apiName getunreads
* @apiGroup SeMail
* @apiDescription 用户在登录/非登录状态下，获取属于自己尚未阅读的消息。
*
* @apiParam {String} username 用户的公钥。
* @apiParam {String} signature 用户对Base64.encode(session-randkey)字符串的签名。
* @apiParam {Number} timestamp 获取通知的时间标签。
* @apiParam {String} addr 获取某指定公钥发送的消息。
* @apiSuccessExample {json} Success-Response:
*     HTTP/1.1 200 OK
*     {
*       "ts": 1549961135034,
*       "data": [
*            {
                 'mid': 10,
                 'sign':"MEQCID2Cd4FQA06Y+N95N5Ids8Dn2y4EUAjuP6G61ufbuHzPAiBqTEK6ncN4a5AQl8hOl12QykVglCcWR5lyXOiZU3hlRwE=",
                 'content':"ThKJDaJK5/RC9YX/P8/9RQQJO0lIXuWFS0S7ixZYNRn……=",	
                 'createdate':1549961135034
*            }
*        ]
*     }
*  @apiError 400 Bad Request 
*/
router.post('/getunreads', function (req, res) {
    if (!req.body || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
        typeof(req.body.username) !== 'string' || req.body.username.length !== 44 ||
        typeof(req.body.signature) !== 'string' ||
        typeof(req.body.addr) !== 'string' || req.body.addr.length !== 44 ||
        req.body.timestamp === null || !utils.isNumber(req.body.timestamp, 10) || req.body.timestamp < 0) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }
    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    var hName = _pubkey.toString('hex');

    mymongodb.getUnreadMessages(hName, req.body.addr, req.body.timestamp, 15, function(err, results){
        if(err){
            return res.sendStatus(400);
        }
        var retData = {};
        if (results.length < 15) {
            retData.ts = -1;
        } else {
            retData.ts = results[results.length - 1].createdate+86400000;
        }
        retData.data = results;
        res.send(JSON.stringify(retData));
    });
});

/**
 * @api {post} /delleavemsgs 07.Delete Message from server
 * @apiName delleavemsgs
 * @apiGroup SeMail
  * @apiDescription 用户在登录/非登录状态下，删除指定编号的通知类消息。
 * 
 * @apiParam {String} username 用户的公钥。
 * @apiParam {String} signature 用户对Base64.encode(session-randkey)字符串的签名。
 * @apiParam {Array} ids 需删除的消息编号集合。
 * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "ret": 'ok',
 *     }
 *  @apiError 400 Bad Request 
 */
router.post('/delleavemsgs', function (req, res) {
    if (!req.body || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
        typeof(req.body.username) !== 'string' || req.body.username.length !== 44 ||
        typeof(req.body.signature) !== 'string' ||
        req.body.ids === null || !isArray(req.body.ids)) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }
    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    var hName = _pubkey.toString('hex');
    mymongodb.deleteLeaveMessageByIDs(hName, req.body.ids, function(err){
        if(err){
            return res.sendStatus(400);
        }
        res.send(JSON.stringify({'ret': 'ok'}));
    });
});


/**
 * @api {post} /leavemessage 08.Leave Message from server
 * @apiName delleavemsgs
 * @apiGroup SeMail
 * @apiDescription 持有凭证的某人给用户留言，这里的某人是未知的。凡持有用户授权凭证的，都可以给指定的用户留言。该留言长度不得超过8192个字符。
 * 
 * @apiParam {String} addr 持有凭证某人的公钥
 * @apiParam {String} signature 持凭者对Base64.encode(session-randkey)字符串的签名。
 * @apiParam {String} objaddr 给哪个公钥用户留言
 * @apiParam {String} content 留言的内容
 * @apiParam {String} contentsign 持凭证人对留言内容的签名
 * @apiParam {String} authsign 被授权留言的凭证
 * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "result": 'ok',
 *     }
 *  @apiError 400 Bad Request 
 */
router.post('/leavemessage', function (req, res) {
    if (!req.body || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
        typeof(req.body.addr) !== 'string' || req.body.addr.length !== 44 ||
        typeof(req.body.objaddr) !== 'string' || req.body.objaddr.length !== 44 ||
        typeof(req.body.contentsign) !== 'string' || typeof(req.body.content) !== 'string' ||
        req.body.content.length > MAX_LIMIT_MESSAGE_LENGTH || req.body.content.length <= 0 ||
        typeof(req.body.authsign) !== 'string' || typeof(req.body.signature) !== 'string') {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.addr, 'base64');
    var _objpubkey = Buffer.from(req.body.objaddr, 'base64');
    if (ecc.isPoint(_pubkey) === false || ecc.isPoint(_objpubkey) === false) {
        return res.sendStatus(400);
    }

    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";
    
    if (verify(_pubkey.toString(), _objpubkey, req.body.authsign) === false) {
        return res.send({"result":"ok"});
    }
    var hName = _objpubkey.toString('hex');
    mymongodb.getUidByUsername(hName, function (err, exists) {
        if (err) {
            return res.sendStatus(400);
        }
        if (!exists) {
            res.send({"result":"ok"});
        } else {
            if (verify(req.body.content, _pubkey, req.body.contentsign) === false) {
                return res.send({"result":"ok"});
            }
            mymongodb.isBlackEmailAddress(hName, _pubkey.toString('hex'), function(err,exists){
                if (err || exists !== null) {
                    return res.sendStatus(400);
                }
                mymongodb.getLeaveMessageCounts(hName, req.body.addr, function(err, count){
                    if (err || count >= MAX_LIMIT_LEAVEMSG_COUNT) {
                        return res.sendStatus(400);
                    }
                    var _ipaddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
                    var timestamp = Date.now();
                    mymongodb.leaveMessage(hName, req.body.addr, req.body.content, req.body.contentsign, _ipaddress, timestamp, function (err, resmid) {
                        if (err) {
                            return res.sendStatus(400);
                        }
                        var websockets = require.main.require('./src/socket.io');
                        if (websockets.server) {
                            websockets.in('sid_' + hName).emit('semsg', JSON.stringify({
                                'cmd': 'newmsg',
                                'data':{
                                    'mid': resmid,
                                    'createdate':timestamp
                                },
                                'pubkey':req.body.addr,
                                'content':req.body.content,
                                "signature":req.body.contentsign
                            }));
                        }
                        res.send({"result":"ok"});
                    });
                });
            });
        }
    });
});


/**
 * @api {post} /downloadattachment 09.Get Attachment Url
 * @apiName downloadattachment
 * @apiGroup SeMail
 * @apiDescription 持有凭证的某人获取指定编号邮件附件的下载地址。
 * 
 * @apiParam {String} addr 持有凭证某人的公钥
 * @apiParam {String} signature 持凭者对Base64.encode(session-randkey)字符串的签名。
 * @apiParam {String} objaddr 指定来自哪个公钥地址留下的附件
 * @apiParam {Number} mid 指定附件的id号 
 * @apiParam {String} authsign 被授权下载的凭证
 * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "url": 'https://google.com/something.data',
 *       "encrypt": true//ture表示附件内容是被加密处理过的，为了防止被滥用
 *     }
 *  @apiError 400 Bad Request 
 */
router.post('/downloadattachment', function (req, res) {
    if (!req.body || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
        typeof(req.body.addr) !== 'string' || req.body.addr.length !== 44 ||
        typeof(req.body.objaddr) !== 'string' || req.body.objaddr.length !== 44 ||
        req.body.mid === null || !utils.isNumber(req.body.mid, 10) || req.body.mid <= 0 ||
        typeof(req.body.authsign) !== 'string' || typeof(req.body.signature) !== 'string') {
        return res.sendStatus(400);
    }
    var _pubkey = Buffer.from(req.body.addr, 'base64');
    var _objpubkey = Buffer.from(req.body.objaddr, 'base64');
    if (ecc.isPoint(_pubkey) === false || ecc.isPoint(_objpubkey) === false) {
        return res.sendStatus(400);
    }

    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    if (verify(_pubkey.toString(), _objpubkey, req.body.authsign) === false) {
        return res.sendStatus(400);
    }
    var hName = _objpubkey.toString('hex');

    mymongodb.getMessageAttachmentInfo(hName, req.body.addr, req.body.mid, function(err, result){
        if (err || result === null) {
            return res.sendStatus(400);
        }

        var srcfile = nconf.get('base_dir') + "encattchment/" + req.body.mid + "_" + result.createdate + ".dat";
        var filename = req.body.mid + "_" + _pubkey.toString('hex') + ".dat";
        var linkfile = nconf.get('upload_path') + "/files/mails/" + filename;
        var _attachmenturl = nconf.get('url') + "/assets/uploads/files/mails/" + filename;
        fs.exists(linkfile, function(exists){
            if(exists){
                res.send({"url":_attachmenturl, "encrypt":result.encrypt});
            }else{
                fs.link(srcfile,linkfile,function(err){
                    if(err){
                        return res.sendStatus(400);
                    }else{
                        res.send({"url":_attachmenturl, "encrypt":result.encrypt});
                    }
                });
            }
        });
    });
});


/**
 * @api {post} /queryattachmentpasswd 10.Query attachment passwordd
 * @apiName queryattachmentpasswd
 * @apiGroup SeMail
 * @apiDescription 获取指定邮件附件的解密密码。当信息被检测合法后，该邮件加密附件的下载地址将被移除。注意对于邮件附件加密不是发邮人的行为，这是服务商为了防止下载机制被发邮人滥用而设置的轻量级加密。
 *
 * @apiParam {String} addr 持有凭证某人的公钥
 * @apiParam {String} objaddr 指定来自哪个公钥地址留下的附件
 * @apiParam {Number} mid 指定附件的id号 
 * @apiParam {Number} filelen 邮件附件内容的下载长度
 * @apiParam {String} filehash 邮件附件内容的下载md5Hash
 * @apiParam {String} signature 获取邮件附件密码的签名凭证
 * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "hash": 'alkdjakdnalksdnad',//邮件附件的解密后md5Hash
 *       "nlen": 123,//邮件附件的解密后真实长度
 *       "passwd": "aaaaa",//邮件附件的解密密码
 *       "signature": "aaaa"//邮件附件生产者对附件的签名，用以检测数据的完整性
 *     }
 *  @apiError 400 Bad Request 
 */
router.post('/queryattachmentpasswd', function (req, res) {
    if (!req.body ||
        typeof(req.body.addr) !== 'string' || req.body.addr.length !== 44 ||
        typeof(req.body.objaddr) !== 'string' || req.body.objaddr.length !== 44 ||
        req.body.mid === null || !utils.isNumber(req.body.mid, 10) || req.body.mid <= 0 ||
        req.body.filelen === null || !utils.isNumber(req.body.filelen, 10) || req.body.filelen <= 0 ||
        typeof(req.body.filehash) !== 'string' || typeof(req.body.signature) !== 'string') {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.addr, 'base64');
    var _objpubkey = Buffer.from(req.body.objaddr, 'base64');
    if (ecc.isPoint(_pubkey) === false || ecc.isPoint(_objpubkey) === false) {
        return res.sendStatus(400);
    }

    if (verify(Buffer.from(JSON.stringify({"hash":req.body.filehash,"len":req.body.filelen}), 'base64').toString(), _pubkey, req.body.signature) === false) {
        return res.sendStatus(400);
    }

    var hName = _objpubkey.toString('hex');

    mymongodb.getMessageAttachmentPassword(hName, req.body.addr, req.body.mid, req.body.filehash, req.body.filelen, function(err, result){
        if (err || result === null) {
            return res.sendStatus(400);
        }
        res.send({"hash":result.uphash,"nlen":result.upcurlen,"passwd":result.passwd,'signature':result.signup});
        var _ipaddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        mymongodb.deleteMessageAttachment(hName, req.body.addr, req.body.mid, req.body.signature, _ipaddress);
        
        fs.unlink(nconf.get('upload_path') + "/files/mails/" + req.body.mid + "_" + _pubkey.toString('hex') + ".dat",function(){});
    });
});

/**
 * @api {post} /uploadattachment 11.Upload attachment
 * @apiName uploadattachment
 * @apiGroup SeMail 
 * @apiDescription 上传邮件附件
 *
 * @apiParam {String} username 上传邮件附件用户的公钥
 * @apiParam {String} signature 用户对附件内容的编号以及上传附件长度的签名。即对"{'mid': mid, 'nlen': 0}"的签名。
 * @apiParam {Number} mid 授权上传的编号
 * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "nlen": 123
 *     }
 *  @apiError 400 Bad Request 
 */
router.post('/uploadattachment', multipartMiddleware, function (req, res) {
    if (!req.body || typeof(req.body.username) !== 'string' || req.body.username.length !== 44 ||
        typeof(req.body.signature) !== 'string' ||
        typeof(req.body.mid) !== 'string') {
        return res.sendStatus(400);
    }

    var mid = parseInt(req.body.mid);
    if (!utils.isNumber(mid, 10) || mid <= 0) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }

    var _hName = _pubkey.toString('hex');
    if (verify(Buffer.from(JSON.stringify({"mid": mid, "nlen": 0}), 'base64').toString(), 
        _pubkey, req.body.signature) === false) {
        return res.sendStatus(400);
    }

    var source = fs.createReadStream(req.files.file.path), dest, distFilename;
    var strpath = nconf.get('base_dir') + "attchmentmsg/";
    //dest = fs.createWriteStream(output);

    mymongodb.getMessageAttachmentAuth(_hName, mid, function (err, result) {
        if (err || typeof(result.uphash) === "undefined") {
            return res.sendStatus(400);
        }

        if (result.upcurlen !== 0 || req.files.file.originalFilename !== mid + "_" + result.uphash + ".dat") {
            return res.sendStatus(400);
        }

        var nSize = req.files.file.size + result.upcurlen;
        if (nSize > result.upmsglen) {
            return res.sendStatus(400);
        }
        else if (nSize < result.upmsglen) {
            distFilename = strpath + mid + "_" + result.uphash + ".tmp";
            dest = fs.createWriteStream(distFilename);
            source.pipe(dest);
            source.on('end', function () {
                fs.unlinkSync(req.files.file.path);
                mymongodb.updateMessageAttachment(_hName, mid, nSize, 0, 0, "", 0, function (err,updateres) {
                    if (err) {
                        fs.unlinkSync(distFilename);
                        return res.sendStatus(400);
                    }
                    if(updateres === 0){
                        res.sendStatus(400);
                    }else {
                        res.send({"nlen": nSize});
                    }
                });
            });
            source.on('error', function () {
                return res.sendStatus(400);
            });
        } else {
            distFilename = strpath + mid + "_" + result.uphash + ".dat";
            dest = fs.createWriteStream(distFilename);
            source.pipe(dest);
            source.on('end', function () {
                fs.unlinkSync(req.files.file.path);

                var rs = fs.createReadStream(distFilename);
                var md5sum = crypto.createHash('md5');
                rs.on('data', function (chunk) {
                    md5sum.update(chunk);
                });
                rs.on('end', function () {
                    if (md5sum.digest('hex').toLowerCase() === result.uphash) {
                        //var encdestpath = nconf.get('upload_path') + "/files/mails/";
                        var encdestpath = nconf.get('base_dir') + "encattchment/";
                        
                        doDealAttachment(distFilename,
                            encdestpath + mid + "_" + result.createdate + ".dat",
                            result.uphash,
                            nSize, 
                            result.passwd,
                            function(err,result){
                                if(err){
                                    fs.unlinkSync(distFilename);
                                    return res.sendStatus(400);
                                }else{                                    
                                    mymongodb.updateMessageAttachment(_hName, mid, nSize, 1, result.encrypt, result.dlhash, result.dllen, function (err,updateres) {
                                        if (err) {
                                            fs.unlinkSync(distFilename);
                                            return res.sendStatus(400);
                                        }
                                        if(updateres === 0){
                                            res.sendStatus(400);
                                        }else {
                                            res.send({"nlen": nSize});
                                        }
                                    });
                                }
                            }
                        );
                    } else {
                        fs.unlinkSync(distFilename);
                    }
                });
                rs.on('error', function () {
                    fs.unlinkSync(distFilename);
                    return res.sendStatus(400);
                });
            });
            source.on('error', function () {
                return res.sendStatus(400);
            });
        }
    });
});


/**
 * @api {post} /uploadattachmentmore 12.Upload attachment more
 * @apiName uploadattachmentmore
 * @apiGroup SeMail
 * @apiDescription 上传更多的邮件附件内容
 * 
 * @apiParam {String} username 上传邮件附件用户的公钥
 * @apiParam {String} signature 用户对附件内容的编号以及上传附件长度的签名。即对"{'mid': mid, 'nlen': nnn}"的签名。
 * @apiParam {Number} mid 授权上传的编号
 * @apiSuccessExample {json} Success-Response:
 *     HTTP/1.1 200 OK
 *     {
 *       "nlen": 123
 *     }
 *  @apiError 400 Bad Request 
 */
router.post('/uploadattachmentmore', multipartMiddleware, function (req, res) {
    if (!req.body || typeof(req.body.username) !== 'string' || req.body.username.length !== 44 ||
        typeof(req.body.signature) !== 'string' ||
        typeof(req.body.mid) !== 'string') {
        return res.sendStatus(400);
    }

    var mid = parseInt(req.body.mid);
    if (!utils.isNumber(mid, 10) || mid <= 0) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }

    var _hName = _pubkey.toString('hex');

    var source = fs.createReadStream(req.files.file.path), dest;
    var strpath = nconf.get('base_dir') + "attchmentmsg/";
    
    mymongodb.getMessageAttachmentAuth(_hName, mid, function (err, result) {
        if (err || typeof(result.uphash) === "undefined") {
            return res.sendStatus(400);
        }
        if (req.files.file.originalFilename !== mid + "_" + result.uphash + ".dat" || result.upcurlen === 0) {
            return res.sendStatus(400);
        }
        
        if (verify(Buffer.from(JSON.stringify({"mid": mid, "nlen": result.upcurlen}), 'base64').toString(), 
            _pubkey, req.body.signature) === false) {
            return res.sendStatus(400);
        }

        var nSize = req.files.file.size + result.upcurlen;
        var distFilename = strpath + mid + "_" + result.uphash + ".tmp";
        if (nSize > result.upmsglen) {
            return res.sendStatus(400);
        }
        else if (nSize < result.upmsglen) {
            dest = fs.createWriteStream(distFilename, {'flags': 'a'});
            source.pipe(dest);
            source.on('end', function () {
                fs.unlinkSync(req.files.file.path);
                mymongodb.updateMessageAttachment(_hName, mid, nSize, 0, 0, "", 0, function (err, updateres) {
                    if (err) {
                        fs.unlinkSync(distFilename);
                        return res.sendStatus(400);
                    }
                    if(updateres === 0){
                        res.sendStatus(400);
                    }else {
                        res.send({"nlen": nSize});
                    }
                });
            });
            source.on('error', function () {
                return res.sendStatus(400);
            });
        } else {
            dest = fs.createWriteStream(distFilename, {'flags': 'a'});
            source.pipe(dest);
            source.on('end', function () {
                fs.unlinkSync(req.files.file.path);
                var rs = fs.createReadStream(distFilename);
                var md5sum = crypto.createHash('md5');
                rs.on('data', function (chunk) {
                    md5sum.update(chunk);
                });
                rs.on('end', function () {
                    if (md5sum.digest('hex').toLowerCase() === result.uphash) {
                        //var encdestpath = nconf.get('upload_path') + "/files/mails/";
                        var encdestpath = nconf.get('base_dir') + "encattchment/";
                        doDealAttachment(distFilename,
                            encdestpath + mid + "_" + result.createdate + ".dat",
                            result.uphash,
                            nSize, 
                            result.passwd,
                            function(err,result){
                                if(err){
                                    fs.unlinkSync(distFilename);
                                    return res.sendStatus(400);
                                }else{                                    
                                    mymongodb.updateMessageAttachment(_hName, mid, nSize, 1, result.encrypt, result.dlhash, result.dllen, function (err,updateres) {
                                        if (err) {
                                            fs.unlinkSync(distFilename);
                                            return res.sendStatus(400);
                                        }
                                        if(updateres === 0){
                                            res.sendStatus(400);
                                        }else {
                                            res.send({"nlen": nSize});
                                        }
                                    });
                                }
                            }
                        );
                    } else {
                        fs.unlinkSync(distFilename);
                    }
                });
                rs.on('error', function () {
                    fs.unlinkSync(distFilename);
                    return res.sendStatus(400);
                });
            });
            source.on('error', function () {
                return res.sendStatus(400);
            });
        }
    });
});

module.exports = router;
