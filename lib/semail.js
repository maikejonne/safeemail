"use strict";

var createHash = require('create-hash'),
    secp256k1 = require('secp256k1'),
    ecc = require('tiny-secp256k1'),
    utils = require('../../public/src/utils'),
    mymongodb = require('./mymongodb'),
    srviosockets = null,
    SEMail = {};

function isArray(object){
    return object && typeof object==='object' &&
        Array === object.constructor;
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

function tryConToJson(strObj) {
    try {
        return JSON.parse(strObj);
    } catch (e) {
        return null;
    }
}

function resetSocketExtData(socket, bInit) {
    if (bInit === false) {
        if (socket.strHaseName !== "") {
            socket.leave('sid_' + socket.strHaseName);
        }
    }
    socket.bStopRecvNetMsg = false;
    socket.bAuth = false;
    socket.dwUID = 0;
    socket.strUserName = null;
    socket.strBase64Name = null;
    socket.strHaseName = "";
    socket.strRandLogin = null;
    socket.dwNumsOfunAuthAvaters = 0;
    socket.dwNumsOfAuthAvaters = 0;
    socket.nLvL = 0;
    socket.gender = 0;
    socket.coins = 0;
    socket.phone = "";
    socket.maxSends = 10;

    socket.bHasErrorMustInterrupt = false;
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

function normalUserLogin(data, socket, callback) {
    var retData = {};
    socket.bStopRecvNetMsg = true;
    var hName = Buffer.from(data.name, 'base64').toString('hex');
    mymongodb.getUidByUsername(hName, function (err, ritem) {
        if (err) {
            destoryClientSocket(socket);
            return;
        }
        if (ritem) {
            socket.strUserName = data.name;
            socket.dwUID = parseInt(ritem.uid, 10);
            socket.strRandLogin = RandString(33);
            retData.rand = socket.strRandLogin;
            socket.bStopRecvNetMsg = false;
            callback(null, JSON.stringify(retData));
        } else {
            destoryClientSocket(socket);
        }
    });
}

function destoryClientSocket (socket) {
    resetSocketExtData(socket, false);
    socket.disconnect();
}

function addSocketToAuthUserList(socket) {
    srviosockets.in('sid_' + socket.strHaseName).clients(function (err, clients) {
        if (clients.length > 0) {
            for (var i = 0; i < clients.length; i++) {
                var _s = srviosockets.of('/').adapter.nsp.connected[clients[i]];
                if (_s) {
                    destoryClientSocket(_s);
                } else {
                    srviosockets.of('/').adapter.remoteDisconnect(clients[i], true);
                }
            }
        }
        socket.join('sid_' + socket.strHaseName);
    });
}

SEMail.onMessage = function (socket, recvdata, callback) {
    if (socket.bHasErrorMustInterrupt === true || typeof(recvdata) !== 'string') {
        destoryClientSocket(socket);
        return;
    }
    var dwUID = socket.dwUID, retData = {},_pubkey,_hName,i;
    var data = tryConToJson(recvdata);
    if (data === null || socket.bStopRecvNetMsg === true) {
        destoryClientSocket(socket);
        return;
    }

    if (data.cmd === 'user.login') {
        if (socket.bAuth === true ||
            typeof(data.name) !== 'string' || data.name.length !== 44) {
            destoryClientSocket(socket);
            return;
        }
        normalUserLogin(data, socket, callback);
    }
    else if (data.cmd === 'user.relogin') {
        if (socket.bAuth === true || socket.strUserName === null ||
             socket.strRandLogin === null || dwUID === 0 ||
              typeof(data.signature) !== 'string') {
            destoryClientSocket(socket);
            return;
        }
        if (verify(socket.strRandLogin, Buffer.from(socket.strUserName, 'base64'), data.signature) === false) {
            destoryClientSocket(socket);
            return;
        }
        socket.strRandLogin = null;

        mymongodb.getUserBaseInfo(dwUID, true, function (err, result) {
            if (err) {
                destoryClientSocket(socket);
                return;
            }
            if (result.auth === 2 || result.auth === 0) {
                destoryClientSocket(socket);
                return;
            }
            else if (result.auth === 3) {
                retData.lvl = 2;
            } else {
                retData.lvl = result.auth;
            }

            socket.nLvL = result.auth;
            socket.gender = result.gender;
            if (typeof(result.phone) === "string") {
                socket.phone = result.phone;
            } else {
                socket.phone = "";
            }

            if (typeof(result.coin) === "number") {
                socket.coins = result.coins;
            } else {
                socket.coins = 0;
            }
            socket.dwNumsOfunAuthAvaters = result.upics.length;
            socket.dwNumsOfAuthAvaters = result.pics.length;

            socket.bAuth = true;
            socket.strBase64Name = Buffer.from(socket.strUserName, 'base64');
            socket.strHaseName = socket.strBase64Name.toString('hex');

            retData.srvtime = new Date().getTime();
            retData.phone = result.phone;
            retData.gender = result.gender;
            retData.coins = result.coins;
            retData.info = result.info;
            retData.upics = result.upics;
            retData.pics = result.pics;

            callback(null, JSON.stringify(retData));
            addSocketToAuthUserList(socket);
            
            mymongodb.updateUserFieldByUID(dwUID,{
                lastonline:Date.now(),
                ip:socket.ip
            });
        });
    }
    else if (data.cmd === 'user.logout') {
        destoryClientSocket(socket);
    }
    else if (data.cmd === 'temporary.auth'){
        if (socket.bAuth === false ||
            typeof(data.content) !== 'string' || data.content.length > 64 ) {
            destoryClientSocket(socket);
            return;
        }

        mymongodb.temporaryAuth(socket.strHaseName, data.content, function(err,result){
            if(err){
                return callback({'message': 'database error.'});
            }
            retData.tid = result.tid;
            return callback(null, JSON.stringify(retData));
        });
    }
    else if (data.cmd === 'cancel.auth'){
        if (socket.bAuth === false || typeof(data.pubkey) !== 'string' ||
            data.pubkey.length !== 44 || data.pubkey === socket.strUserName) {
            destoryClientSocket(socket);
            return;
        }
        _pubkey = Buffer.from(data.pubkey, 'base64');
        if (ecc.isPoint(_pubkey) === false) {
            destoryClientSocket(socket);
            return;
        }
        _hName = _pubkey.toString('hex');

        mymongodb.setAddressToBlack(_hName, socket.strHaseName, function(err){
            if(err){
                return callback({'message': 'database error.'});
            }
            retData.result = 1;
            return callback(null, JSON.stringify(retData));
        });
    }
    else if (data.cmd === 'remove.blacklist'){
        if (socket.bAuth === false || typeof(data.pubkey) !== 'string' ||
            data.pubkey.length !== 44 || data.pubkey === socket.strUserName) {
            destoryClientSocket(socket);
            return;
        }
        _pubkey = Buffer.from(data.pubkey, 'base64');
        if (ecc.isPoint(_pubkey) === false) {
            destoryClientSocket(socket);
            return;
        }
        _hName = _pubkey.toString('hex');

        mymongodb.removeAddressFromBlack(_hName, socket.strHaseName, function(err,result){
            if(err){
                return callback({'message': 'database error.'});
            }
            retData.result = result;
            return callback(null, JSON.stringify(retData));
        });
    }
    else if(data.cmd === 'new.mail') {
        if (socket.bAuth === false || typeof(data.hash) !== 'string' ||
            typeof(data.signature) !== 'string'||
            data.objects === null || !isArray(data.objects) || data.objects.length === 0 || data.objects.length > socket.maxSends ||
            data.msglen === null || !utils.isNumber(data.msglen, 10) || data.msglen <= 0 || data.msglen >= 40960000 ) {
            destoryClientSocket(socket);
            return;
        }
        for(i=0;i<data.objects.length;i++){
            if(typeof(data.objects[i]) !== 'string' || data.objects[i].length !== 44 || data.objects[i] === socket.strUserName)
            {
                destoryClientSocket(socket);
                return;
            }
        }

        if (verify(Buffer.from(JSON.stringify({"hash":data.hash,"len":data.msglen}), 'base64').toString(), 
            Buffer.from(socket.strUserName, 'base64'), data.signature) === false) {
            destoryClientSocket(socket);
            return;
        }

        mymongodb.createNewMailMessage(socket.strHaseName, data.objects, data.msglen, data.hash, data.signature, socket.ip, function (err, result) {
            if (err) {
                callback({'message': 'new mail error.'});
            } else {
                callback(null, JSON.stringify({mid: result.mid}));
            }
        });
    } else {
        destoryClientSocket(socket);
    }
};

SEMail.onConnect = function (socket) {
    resetSocketExtData(socket, true);
};

SEMail.onDisConnect = function (socket) {
    if (socket.dwUID === 0){
        return false;
    }
    resetSocketExtData(socket, false);
    return true;
};

SEMail.init = function (io) {
    srviosockets = io;
};


module.exports = SEMail;
