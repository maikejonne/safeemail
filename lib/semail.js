"use strict";

var createHash = require('create-hash'),
	secp256k1 = require('secp256k1'),
	ecc = require('tiny-secp256k1'),
	utils = require('../../public/src/utils'),
	mymongodb = require('./mymongodb'),
	srviosockets = null,
	SEMAIL_TOP_CATEGORY = 6,
	SEMAIL_TOP_AD_CATEGORY = 7,
	SEMAIL_AD_CATEGORY_MAX = 8,
	SEMAIL_TOP_GENERAL_CATEGORY = 8,
	SEMail = {};

function releaseExpireSession(){
	setTimeout(function(){
		mymongodb.deleteExpireMailSession(function(){
			releaseExpireSession();
		});
	},300000);
}

function isArray(object) {
	return object && typeof object === 'object' &&
		Array === object.constructor;
}

function verify(message, pubBuffer, signature) {
	try {
		var hash = createHash('sha256').update(Buffer.from(message)).digest();

		return secp256k1.verifySync(hash,
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
		if(socket.connections !== null){
			for (var value of socket.connections.values()) {
				value.conn.destroy();
			}
			socket.connections.clear();
		}
		if(socket.sessionInterval !== null){
			clearTimeout(socket.sessionInterval);
		}
	}
	socket.bStopRecvNetMsg = false;
	socket.bAuth = false;
	socket.dwUID = 0;
	socket.strUserName = null;
	socket.strBase64Name = null;
	socket.strHaseName = "";
	socket.strRandLogin = null;
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
			retData.rkey = RandString(Math.floor((Math.random()*500)+1));
			socket.bStopRecvNetMsg = false;
			callback(null, JSON.stringify(retData));
		} else {
			destoryClientSocket(socket);
		}
	});
}

function destoryClientSocket(socket) {
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
	if (socket.bHasErrorMustInterrupt === true || typeof (recvdata) !== 'string') {
		destoryClientSocket(socket);
		return;
	}
	var dwUID = socket.dwUID,
		retData = {},
		_pubkey, _hName, i;

	var data = tryConToJson(recvdata);
	if (data === null || socket.bStopRecvNetMsg === true) {
		destoryClientSocket(socket);
		return;
	}
	
	if (data.cmd === 'user.login') {
		if ( dwUID !== 0 || socket.bAuth === true ||
			typeof (data.name) !== 'string' || data.name.length !== 44) {
			destoryClientSocket(socket);
			return;
		}
		normalUserLogin(data, socket, callback);
	} else if (data.cmd === 'user.relogin') {
		if (socket.bAuth === true || socket.strUserName === null ||
			socket.strRandLogin === null || dwUID === 0 ||
			typeof (data.signature) !== 'string') {
			destoryClientSocket(socket);
			return;
		}
		if (verify(socket.strRandLogin, Buffer.from(socket.strUserName, 'base64'), data.signature) === false) {
			destoryClientSocket(socket);
			return;
		}
		socket.strRandLogin = null;

		socket.bAuth = true;
		socket.strBase64Name = Buffer.from(socket.strUserName, 'base64');
		socket.strHaseName = socket.strBase64Name.toString('hex');

		retData.srvtime = new Date().getTime();
		retData.rkey = RandString(Math.floor((Math.random()*500)+1));
		
		callback(null, JSON.stringify(retData));
		addSocketToAuthUserList(socket);

		mymongodb.updateUserFieldByUID(dwUID, {
			lastonline: Date.now(),
			ip: socket.ip
		});
	} else if (data.cmd === 'user.logout') {
		if (socket.bAuth === false) {
			return destoryClientSocket(socket);
		}
		destoryClientSocket(socket);
	} else if (data.cmd === 'temporary.auth') {
		if (socket.bAuth === false ||
			typeof (data.content) !== 'string' || data.content.length > 64) {
			destoryClientSocket(socket);
			return;
		}
		
		mymongodb.createNewTemporaryAuth(socket.strHaseName, data.content, function (err, result) {
			if (err) {
				return callback({
					'message': 'database error.'
				});
			}
			retData.tid = result.tid;
			return callback(null, JSON.stringify(retData));
		});
	} else if (data.cmd === 'cancel.auth') {
		if (socket.bAuth === false || typeof (data.pubkey) !== 'string' ||
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

		mymongodb.setAddressToBlack(_hName, socket.strHaseName, function (err) {
			if (err) {
				return callback({
					'message': 'database error.'
				});
			}
			retData.result = 1;
			return callback(null, JSON.stringify(retData));
		});
	} else if (data.cmd === 'remove.blacklist') {
		if (socket.bAuth === false || typeof (data.pubkey) !== 'string' ||
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

		mymongodb.removeAddressFromBlack(_hName, socket.strHaseName, function (err, result) {
			if (err) {
				return callback({
					'message': 'database error.'
				});
			}
			retData.result = result;
			return callback(null, JSON.stringify(retData));
		});
	} else if (data.cmd === 'new.mail') {
		if (socket.bAuth === false || typeof (data.hash) !== 'string' ||
			typeof (data.signature) !== 'string' ||
			data.objects === null || !isArray(data.objects) || data.objects.length === 0 || data.objects.length > socket.maxSends ||
			data.msglen === null || !utils.isNumber(data.msglen, 10) || data.msglen <= 0 || data.msglen >= 40960000) {
			destoryClientSocket(socket);
			return;
		}
		for (i = 0; i < data.objects.length; i++) {
			if (typeof (data.objects[i]) !== 'string' || data.objects[i].length !== 44 || data.objects[i] === socket.strUserName) {
				destoryClientSocket(socket);
				return;
			}
		}

		if (verify(JSON.stringify({
					"hash": data.hash,
					"len": data.msglen
				}),
				Buffer.from(socket.strUserName, 'base64'), data.signature) === false) {
			destoryClientSocket(socket);
			return;
		}

		mymongodb.createNewMailMessage(socket.strHaseName, data.objects, data.msglen, data.hash, data.signature, socket.ip, function (err, result) {
			if (err) {
				callback({
					'message': 'new mail error.'
				});
			} else {
				callback(null, JSON.stringify({
					mid: result.mid
				}));
			}
		});
	} else if(data.cmd === 'querycategory') {
		if (socket.bAuth === false || typeof (data.type) !== 'string' ||
			data.time === null || !utils.isNumber(data.time, 10) || data.time < 0 ) {
			destoryClientSocket(socket);
			return;
		}
		if(data.type === 'top'){
			mymongodb.aggregateAdTop(SEMAIL_TOP_CATEGORY, false, 1, function (err, ret) {
				if (err) {
					return callback({
						'message': 'query error.'
					});
				}
				mymongodb.queryPostFromFourmArticles(ret, 0, function (err) {
					if (err) {
						return callback({
							'message': 'query error.'
						});
					}
					for (i = ret.length - 1; i >= 0; i--) {
						if (ret.pid === 0) {
							ret.splice(i, 1);
						}
					}
					retData.data = ret;
					callback(null, JSON.stringify(retData));
				});
			});
		} else if(data.type === 'moretop'){
			mymongodb.aggregateAdTop(SEMAIL_TOP_AD_CATEGORY, false, SEMAIL_AD_CATEGORY_MAX, function (err, ret) {
				if (err) {
					return callback({
						'message': 'query error.'
					});
				}
				mymongodb.queryPostFromFourmArticles(ret, 0, function (err) {
					if (err) {
						return callback({
							'message': 'query error.'
						});
					}
					for (i = ret.length - 1; i >= 0; i--) {
						if (ret.pid === 0) {
							ret.splice(i, 1);
						}
					}
					retData.data = ret;
					callback(null, JSON.stringify(retData));
				});
			});
		} else if(data.type === 'general'){
			mymongodb.queryHeadlinesArticles(SEMAIL_TOP_GENERAL_CATEGORY, data.time, false, false, function (err, result) {
				if (err) {
					return callback({
						'message': 'query error.'
					});
				}
				mymongodb.queryPostFromFourmArticles(result, 2, function (err) {
					if (err) {
						return callback({
							'message': 'query error.'
						});
					}
					if (result.length < 10) {
						retData.ts = -1;
					} else {
						retData.ts = result[result.length - 1].timestamp;
					}
					for (i = result.length - 1; i >= 0; i--) {
						if (result[i].pid === 0) {
							result.splice(i, 1);
						}
					}
					retData.data = result;
					callback(null, JSON.stringify(retData));
				});
			});
		}else{
			destoryClientSocket(socket);	
		}
	} else {
		destoryClientSocket(socket);
	}
};

SEMail.onConnect = function (socket) {
	resetSocketExtData(socket, true);
};

SEMail.onDisConnect = function (socket) {
	if (socket.dwUID === 0 && socket.dwWSPUID === 0) {
		return false;
	}

	resetSocketExtData(socket, false);
	return true;
};

SEMail.init = function (io) {
	srviosockets = io;

	mymongodb.deleteAllMailSession();
	releaseExpireSession();
};


module.exports = SEMail;
