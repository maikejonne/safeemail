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
    eccrypto = require("eccrypto"),
    Blowfish = require('javascript-blowfish'),
    markdown = require("markdown").markdown,
    multipart = require('connect-multiparty'),
    multipartMiddleware = multipart(),
    mymongodb = require('./mymongodb'),
    xxtea = require('./xxtea'),
    MAX_LIMIT_NOTICE_LENGTH = 2048,
    MAX_LIMIT_MESSAGE_LENGTH = 8192,
    MAX_LIMIT_LEAVEMSG_COUNT = 50,
    xinge = require('./xinge'),
    xingeApp = new xinge.XingeApp(000000000001, "????????????"),
    xingeAndroidApp = new xinge.XingeApp(000000000002, "?????????");


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

function RandString(strlen) {
    var strRandKey = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var maxPos = strRandKey.length;
    var strRet = '';
    for (var i = 0; i < strlen; i++) {
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
}

function getSession(req, res){
    req.session.randkey = RandString(32);
    res.send({"session": req.session.randkey});
}

function doReg(req, res){
    if (!req.body.data || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 || typeof(req.body.data.username) !== 'string' || req.body.data.username.length !== 44 ||
        typeof(req.body.data.signature) !== 'string') {
        return res.sendStatus(400);
    }
    var _pubkey = Buffer.from(req.body.data.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }
    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.data.signature) === false) {
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
}

function doTempAuth(req, res){
    if (!req.body.data || typeof(req.body.data.name) !== 'string' || req.body.data.name.length !== 44 ||
    typeof(req.body.data.signature) !== 'string' || typeof(req.body.data.data) !== 'string' ||
    req.body.data.data.length > MAX_LIMIT_NOTICE_LENGTH || req.body.data.data.length <= 0 ||
    typeof(req.body.data.tid) !== 'number' || !utils.isNumber(req.body.data.tid, 10) || req.body.data.tid <= 0) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.data.name, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }

    var _hName = _pubkey.toString('hex');
    mymongodb.queryTemporaryAuthByIDAndName(req.body.data.tid, _hName, function(err, result){
        if(err){
            return res.sendStatus(400);
        }
        if(typeof(result.content) !== 'string'){
            return res.sendStatus(400);
        }

        if (verify(Buffer.from(result.content, 'base64').toString(), _pubkey, req.body.data.signature) === false) {
            return res.sendStatus(400);
        }
        mymongodb.updateTemporaryAuthByID(req.body.data.tid, req.body.data.signature, req.body.data.data, function(err, updateres){
            if(err){
                return res.sendStatus(400);
            }
            if(updateres === 0){
                res.sendStatus(400);
            }else {
                res.send({"ret": updateres});
                mymongodb.queryDeviceTokenByName(_hName,function(err,restoken){
                    if(err !== null || typeof(restoken.token) !== 'string'){
                        var websockets = require.main.require('./src/socket.io');
                        if (websockets.server) {
                            websockets.in('sid_' + _hName).emit('semsg', JSON.stringify({
                                'cmd': 'authmsg',
                                'tid': req.body.data.tid,
                                'data':req.body.data.data
                            }));
                        }
                    }else{
                        if(restoken.platform === 'ios'){
                            var iOSMessage = new xinge.IOSMessage();
                            iOSMessage.alert = restoken.lang==='zh'?'有新的消息，请查收':'Receive new message';
                            iOSMessage.sound = 'default';
                            xingeApp.pushToSingleDevice(restoken.token, iOSMessage, xinge.IOS_ENV_PRO, function(err){
                                if(err===null){
                                    mymongodb.updateDeviceTokenLastPush(restoken.tid,_hName);
                                }
                            });
                        }
                        else if(restoken.platform === 'android'){
                            var androidAction = new xinge.ClickAction();
                            androidAction.actionType = xinge.ACTION_TYPE_ACTIVITY;

                            var androidMessage = new xinge.AndroidMessage();
                            androidMessage.type = xinge.MESSAGE_TYPE_NOTIFICATION;
                            androidMessage.action = androidAction;
                            androidMessage.style = new xinge.Style();
                            androidMessage.title = androidMessage.content = restoken.lang==='zh'?'有新的消息，请查收':'Receive new message';

                            xingeAndroidApp.pushToSingleDevice(restoken.token, androidMessage, 0, function(err){
                                if(err===null){
                                    mymongodb.updateDeviceTokenLastPush(restoken.tid,_hName);
                                }
                            });
                        }
                    }
                });
            }
        });
    });
}

function doGetNotices(req, res){
    if (!req.body.data || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
        typeof(req.body.data.username) !== 'string' || req.body.data.username.length !== 44 ||
        typeof(req.body.data.signature) !== 'string' ||
        req.body.data.timestamp === null || !utils.isNumber(req.body.data.timestamp, 10) || req.body.data.timestamp < 0) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.data.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }
    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.data.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    var hName = _pubkey.toString('hex');
    mymongodb.queryTemporaryAuthUnnotices(hName, req.body.data.timestamp, 15, function(err, results){
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
}

function doDelNotices(req, res){
    if (!req.body.data || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
        typeof(req.body.data.username) !== 'string' || req.body.data.username.length !== 44 ||
        typeof(req.body.data.signature) !== 'string' ||
        req.body.data.ids === null || !isArray(req.body.data.ids)) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.data.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }
    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.data.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    var hName = _pubkey.toString('hex');
    mymongodb.deleteTemporaryAuthNotices(req.body.data.ids, hName, function(err){
        if(err){
            return res.sendStatus(400);
            //return res.send(JSON.stringify({'errmsg': 'refresh data error.'}));
        }
        res.send(JSON.stringify({'ret': 'ok'}));
    });
}

function doGetUnreads (req, res) {
    if (!req.body.data || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
    typeof(req.body.data.username) !== 'string' || req.body.data.username.length !== 44 ||
    typeof(req.body.data.signature) !== 'string' ||
    typeof(req.body.data.addr) !== 'string' || req.body.data.addr.length !== 44 ||
    req.body.data.timestamp === null || !utils.isNumber(req.body.data.timestamp, 10) || req.body.data.timestamp < 0) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.data.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }
    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.data.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    var hName = _pubkey.toString('hex');

    mymongodb.getUnreadMessages(hName, req.body.data.addr, req.body.data.timestamp, 15, function(err, results){
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
}

function doGetMoreUnreads(req, res) {
    if (!req.body.data || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
        typeof(req.body.data.username) !== 'string' || req.body.data.username.length !== 44 ||
        typeof(req.body.data.signature) !== 'string' ||
        req.body.data.addrs === null || !isArray(req.body.data.addrs) || req.body.data.addrs.length === 0 || req.body.data.addrs.length > 50) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.data.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }
    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.data.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    var hName = _pubkey.toString('hex');

    for (var i = 0; i < req.body.data.addrs; i++) {
        if(typeof(req.body.data.addrs[i]) !== 'string' || req.body.data.addrs[i].length !== 44){
            return res.sendStatus(400);
        }
    }

    mymongodb.getFriendsUnreads(hName, req.body.data.addrs, function(err, results){
        if(err){
            return res.sendStatus(400);
        }
        res.send(JSON.stringify({'addrs': results}));
    });
}

function doDelLeaveMsgs(req, res) {
    if (!req.body.data || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
        typeof(req.body.data.username) !== 'string' || req.body.data.username.length !== 44 ||
        typeof(req.body.data.signature) !== 'string' ||
        req.body.data.ids === null || !isArray(req.body.data.ids)) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.data.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }
    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.data.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    var hName = _pubkey.toString('hex');
    mymongodb.deleteLeaveMessageByIDs(hName, req.body.data.ids, function(err){
        if(err){
            return res.sendStatus(400);
        }
        res.send(JSON.stringify({'ret': 'ok'}));
    });
}

function doLeaveMessage(req, res) {
    if (!req.body.data || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
    typeof(req.body.data.addr) !== 'string' || req.body.data.addr.length !== 44 ||
    typeof(req.body.data.objaddr) !== 'string' || req.body.data.objaddr.length !== 44 ||
    typeof(req.body.data.contentsign) !== 'string' || typeof(req.body.data.content) !== 'string' ||
    req.body.data.content.length > MAX_LIMIT_MESSAGE_LENGTH || req.body.data.content.length <= 0 ||
    typeof(req.body.data.authsign) !== 'string' || typeof(req.body.data.signature) !== 'string') {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.data.addr, 'base64');
    var _objpubkey = Buffer.from(req.body.data.objaddr, 'base64');
    if (ecc.isPoint(_pubkey) === false || ecc.isPoint(_objpubkey) === false) {
        return res.sendStatus(400);
    }

    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.data.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    if (verify(_pubkey.toString(), _objpubkey, req.body.data.authsign) === false) {
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
            if (verify(req.body.data.content, _pubkey, req.body.data.contentsign) === false) {
                return res.send({"result":"ok"});
            }
            mymongodb.isBlackEmailAddress(hName, _pubkey.toString('hex'), function(err,exists){
                if (err || exists !== null) {
                    return res.sendStatus(400);
                }
                mymongodb.getLeaveMessageCounts(hName, req.body.data.addr, function(err, count){
                    if (err || count >= MAX_LIMIT_LEAVEMSG_COUNT) {
                        return res.sendStatus(400);
                    }
                    var _ipaddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
                    var timestamp = Date.now();
                    mymongodb.leaveMessage(hName, req.body.data.addr, req.body.data.content, req.body.data.contentsign, _ipaddress, timestamp, function (err, resmid) {
                        if (err) {
                            return res.sendStatus(400);
                        }

                        mymongodb.queryDeviceTokenByName(hName,function(err,restoken){
                            if(err !==null || typeof(restoken.token) !== 'string'){
                                var websockets = require.main.require('./src/socket.io');
                                if (websockets.server) {
                                    websockets.in('sid_' + hName).emit('semsg', JSON.stringify({
                                        'cmd': 'newmsg',
                                        'data':{
                                            'mid': resmid,
                                            'createdate':timestamp
                                        },
                                        'pubkey':req.body.data.addr,
                                        'content':req.body.data.content,
                                        "signature":req.body.data.contentsign
                                    }));
                                }
                            }else{
                                if(restoken.platform === 'ios'){
                                    var iOSMessage = new xinge.IOSMessage();
                                    iOSMessage.alert = restoken.lang==='zh'?'有新的消息，请查收':'Receive a new message';
                                    iOSMessage.sound = 'default';
                                    xingeApp.pushToSingleDevice(restoken.token, iOSMessage, xinge.IOS_ENV_PRO, function(err){
                                        if(err===null){
                                            mymongodb.updateDeviceTokenLastPush(restoken.tid,hName);
                                        }
                                    });
                                }
                                else if(restoken.platform === 'android'){
                                    var androidAction = new xinge.ClickAction();
                                    androidAction.actionType = xinge.ACTION_TYPE_ACTIVITY;
        
                                    var androidMessage = new xinge.AndroidMessage();
                                    androidMessage.type = xinge.MESSAGE_TYPE_NOTIFICATION;
                                    androidMessage.action = androidAction;
                                    androidMessage.style = new xinge.Style();
                                    androidMessage.title = androidMessage.content = restoken.lang==='zh'?'有新的消息，请查收':'Receive a new message';
        
                                    xingeAndroidApp.pushToSingleDevice(restoken.token, androidMessage, 0, function(err){
                                        if(err===null){
                                            mymongodb.updateDeviceTokenLastPush(restoken.tid,hName);
                                        }
                                    });        
                                }
                            }
                        });

                        res.send({"result":"ok"});
                    });
                });
            });
        }
    });
}

function doDownloadAttachment(req, res) {
    if (!req.body.data || !req.session || typeof(req.session.randkey) !== "string" || req.session.randkey.length !== 32 ||
        typeof(req.body.data.addr) !== 'string' || req.body.data.addr.length !== 44 ||
        typeof(req.body.data.objaddr) !== 'string' || req.body.data.objaddr.length !== 44 ||
        req.body.data.mid === null || !utils.isNumber(req.body.data.mid, 10) || req.body.data.mid <= 0 ||
        typeof(req.body.data.authsign) !== 'string' || typeof(req.body.data.signature) !== 'string') {
        return res.sendStatus(400);
    }
    var _pubkey = Buffer.from(req.body.data.addr, 'base64');
    var _objpubkey = Buffer.from(req.body.data.objaddr, 'base64');
    if (ecc.isPoint(_pubkey) === false || ecc.isPoint(_objpubkey) === false) {
        return res.sendStatus(400);
    }

    if (verify(Buffer.from(req.session.randkey, 'base64').toString(), _pubkey, req.body.data.signature) === false) {
        return res.sendStatus(400);
    }
    req.session.randkey = "";

    if (verify(_pubkey.toString(), _objpubkey, req.body.data.authsign) === false) {
        return res.sendStatus(400);
    }
    var hName = _objpubkey.toString('hex');

    mymongodb.getMessageAttachmentInfo(hName, req.body.data.addr, req.body.data.mid, function(err, result){
        if (err || result === null) {
            return res.sendStatus(400);
        }

        var srcfile = nconf.get('base_dir') + "encattchment/" + req.body.data.mid + "_" + result.createdate + ".dat";
        var filename = req.body.data.mid + "_" + _pubkey.toString('hex') + ".dat";
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
}

function doQueryAttachmentPassword(req, res) {
    if (!req.body.data ||
        typeof(req.body.data.addr) !== 'string' || req.body.data.addr.length !== 44 ||
        typeof(req.body.data.objaddr) !== 'string' || req.body.data.objaddr.length !== 44 ||
        req.body.data.mid === null || !utils.isNumber(req.body.data.mid, 10) || req.body.data.mid <= 0 ||
        req.body.data.filelen === null || !utils.isNumber(req.body.data.filelen, 10) || req.body.data.filelen <= 0 ||
        typeof(req.body.data.filehash) !== 'string' || typeof(req.body.data.signature) !== 'string') {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(req.body.data.addr, 'base64');
    var _objpubkey = Buffer.from(req.body.data.objaddr, 'base64');
    if (ecc.isPoint(_pubkey) === false || ecc.isPoint(_objpubkey) === false) {
        return res.sendStatus(400);
    }

    if (verify(Buffer.from(JSON.stringify({"hash":req.body.data.filehash,"len":req.body.data.filelen}), 'base64').toString(), _pubkey, req.body.data.signature) === false) {
        return res.sendStatus(400);
    }

    var hName = _objpubkey.toString('hex');

    mymongodb.getMessageAttachmentPassword(hName, req.body.data.addr, req.body.data.mid, req.body.data.filehash, req.body.data.filelen, function(err, result){
        if (err || result === null) {
            return res.sendStatus(400);
        }
        res.send({"hash":result.uphash,"nlen":result.upcurlen,"passwd":result.passwd,'signature':result.signup});
        var _ipaddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        mymongodb.deleteMessageAttachment(hName, req.body.data.addr, req.body.data.mid, req.body.data.signature, _ipaddress);
        
        fs.unlink(nconf.get('upload_path') + "/files/mails/" + req.body.data.mid + "_" + _pubkey.toString('hex') + ".dat",function(){});
    });
}

function doUploadAttachment(req, res) {
    if(!req.body.data){
        return res.sendStatus(400);
    }
    
    var _data = tryConToJson(req.body.data);
    if(_data === null){
        return res.sendStatus(400);
    }

    if (typeof(_data.username) !== 'string' || _data.username.length !== 44 ||
        typeof(_data.signature) !== 'string' ||
        typeof(_data.mid) !== 'number') {
        return res.sendStatus(400);
    }

    var mid = _data.mid;
    if (mid <= 0) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(_data.username, 'base64');
    if (ecc.isPoint(_pubkey) === false) {
        return res.sendStatus(400);
    }

    var _hName = _pubkey.toString('hex');
    if (verify(Buffer.from(JSON.stringify({"mid": mid, "nlen": 0}), 'base64').toString(), 
        _pubkey, _data.signature) === false) {
        return res.sendStatus(400);
    }

    var source = fs.createReadStream(req.files.file.path), dest, distFilename;
    var strpath = nconf.get('base_dir') + "attchmentmsg/";

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
}

function doUploadAttachmentMore(req, res){
    if(!req.body.data){
        return res.sendStatus(400);
    }
    
    var _data = tryConToJson(req.body.data);
    if(_data === null){
        return res.sendStatus(400);
    }

    if (typeof(_data.username) !== 'string' || _data.username.length !== 44 ||
        typeof(_data.signature) !== 'string' ||
        typeof(_data.mid) !== 'number') {
        return res.sendStatus(400);
    }

    var mid = _data.mid;
    if (mid <= 0) {
        return res.sendStatus(400);
    }

    var _pubkey = Buffer.from(_data.username, 'base64');
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
            _pubkey, _data.signature) === false) {
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
}

router.post('/', multipartMiddleware, function (req, res) {
    if (!req.body || typeof(req.body.cmd) !== 'string'){
        return res.sendStatus(400);
    }
    if(req.body.cmd === 'session'){
        getSession(req, res);
    }
    else if(req.body.cmd === 'reg'){
        doReg(req, res);
    }
    else if( req.body.cmd === 'tempauth'){
        doTempAuth(req, res);
    }
    else if( req.body.cmd === 'getnotices'){
        doGetNotices(req, res);
    }
    else if( req.body.cmd === 'delnotices'){
        doDelNotices(req, res);
    }
    else if( req.body.cmd === 'getunreads'){
        doGetUnreads(req, res);
    }
    else if( req.body.cmd === 'getmoreunreads'){
        doGetMoreUnreads(req, res);
    }
    else if( req.body.cmd === 'delleavemsgs'){
        doDelLeaveMsgs(req, res);
    }
    else if( req.body.cmd === 'leavemessage'){
        doLeaveMessage(req, res);
    }
    else if( req.body.cmd === 'downloadattachment'){
        doDownloadAttachment(req, res);
    }
    else if( req.body.cmd === 'queryattachmentpasswd'){
        doQueryAttachmentPassword(req, res);
    }
    else if( req.body.cmd === 'uploadattachment'){
        doUploadAttachment(req, res);
    }
    else if( req.body.cmd === 'uploadattachmentmore'){
        doUploadAttachmentMore(req, res);
    }
    else{
        return res.sendStatus(400);
    }
});

module.exports = router;
