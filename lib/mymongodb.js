"use strict";

var async = require('async'),
	db = require('../../src/database'),
	markdown = require("markdown").markdown;

(function (mymongodb) {

	function _tryConvertStrToJson(strObj){
		try{
			return JSON.parse(strObj);
		}catch(e){
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
	
	mymongodb.deleteMessageAttachment = function(fromname, toname, mid, signature, ipaddress, callback){
		callback = callback || function() {};
		db.client.collection('semail').updateOne(
			{
				'_key':'msg:' + mid,
				'from':fromname,
				'toothers':{'$in':[toname]}
			},
			{
				$addToSet:{
					'downs':toname,
					'downsigns':signature+";"+ipaddress
				}
			},
			function(err,res){
				if(err) {
					return callback(err);
				}
				callback(null, res.result.nModified);
			}
		);
	};

	mymongodb.getMessageAttachmentPassword = function(fromname, toname, mid, hash, nlen, callback){
		callback = callback || function() {};
		var _query = {
			'_key':'msg:' + mid,
			'from':fromname,
			'toothers':{'$in':[toname]},
			'downs':{'$nin':[toname]},
			'uploaded':1,
			'dlhash':hash,
			'dllen':nlen,
			'deleted':0,
			'expire':{'$gt': Date.now()}
		};
		db.client.collection('semail').findOne(_query,
			{
				'projection': {
					'_id': 0,
					'uphash': 1,
					'upcurlen': 1,
					'passwd': 1,
					'signup': 1,
					'createdate': 1
				}
			},
			function(err, item){
				if (err) {
					return callback(err);
				}
				callback(null,item);
			}
		);
	};

	mymongodb.getMessageAttachmentInfo = function(fromname, toname, mid, callback){
		callback = callback || function() {};
		var _query = {
			'_key':'msg:' + mid,
			'from':fromname,
			'toothers':{'$in':[toname]},
			'downs':{'$nin':[toname]},
			'uploaded':1,
			'deleted':0,
			'expire':{'$gt': Date.now()}
		};
		db.client.collection('semail').findOne(_query,
			{
				'projection': {
					'_id': 0,
					'encrypt': 1,
					'createdate': 1
				}
			},
			function(err, item){
				if (err) {
					return callback(err);
				}
				callback(null,item);
			}
		);
	};

	mymongodb.updateMessageAttachment = function(name, mid, curlen, nFinish, encrypt, dlhash, dllen, callback){
		callback = callback || function() {};
		var _data = {
			'upcurlen': curlen
		};
		if(nFinish === 1){
			_data.uploaded = 1;
			_data.dlhash = dlhash;
			_data.dllen = dllen;
			_data.encrypt = encrypt;
		}

		db.client.collection('semail').updateOne(
			{
				'_key':'msg:' + mid,
				'from': name,
				'uploaded':0,
				'deleted':0
			},
			{
				$set:_data
			},
			function(err, res){
				if(err) {
					return callback(err);
				}
				callback(null, res.result.nModified);
			}
		);
	};

	mymongodb.getMessageAttachmentAuth = function(name, mid, callback){
		callback = callback || function() {};
		db.client.collection('semail').findOne({
				'_key':'msg:' + mid,
				'from':name,
				'uploaded':0,
				'deleted':0,
				'upexpire':{'$gt': Date.now()}
			},
			{
				'projection': {
					'_id': 0,
					'uphash': 1,
					'upcurlen': 1,
					'upmsglen': 1,
					'passwd':1,
					'createdate':1
				}
			},
			function(err, item){
				if (err) {
					return callback(err);
				}
				item = item || {};
				callback(null,item);
			}
		);
	};
	
		
	mymongodb.createNewMailMessage = function(fromname, toothers, msglen, hash, upsign, ipaddress, callback){
		var _now = Date.now();
		var data = {
			'uphash':hash,
			'upmsglen':msglen,
			'upcurlen':0,
			'uploaded':0,
			'from':fromname,
			'toothers':toothers,
			'expire': _now+86400000,
			'createdate':_now,
			'upexpire':_now+1800000,
			'ip':ipaddress,
			'dlhash':"",
			'dllen':0,
			'encrypt':0,
			'passwd':RandString(16),
			'downs':[],
			'downsigns':[],
			'signup':upsign,
			'deleted': 0,
			'deldate':0
		};
		async.waterfall([
			function (next) {
				db.incrObjectField('global', 'semail_nextMsgid', next);
			},
			function (mid, next) {
				data.mid = mid;
				db.client.collection('semail').updateOne(
					{
						_key: 'msg:' + mid
					},
					{
						$set:data
					},
					{
						upsert: true, w: 1
					},
					function(err){
						if(err) {
							return callback(err);
						}
						next(null, data);
					});
			}
		], callback);
	};

	mymongodb.queryTemporaryAuthByIDAndName = function(tid, hexname, callback){
		var _now = Date.now();
		var _query = {
			'_key': 'tempauth:' + tid,
			'name': hexname,
			'delete':0,
			'expire':{'$gt': _now}
		};

		db.client.collection('semail').findOne(
			_query,
			{
				'projection': {
					'_id': 0,
					'content': 1
				}
			},
			function(err, item){
				if (err) {
					return callback(err);
				}
				item = item || {};
				callback(null,item);
			}
		);
	};

	mymongodb.updateTemporaryAuthByID = function(tid, signature, msg, callback){
		db.client.collection('semail').updateOne(
			{
				'_key': 'tempauth:' + tid,
				'delete':0
			},
			{
				$set:{
					'delete': 1,
					'signature':signature,
					'message':msg
				}
			},
			function(err,res){
				if(err) {
					return callback(err);
				}
				callback(null, res.result.nModified);
			}
		);
	};

	mymongodb.deleteTemporaryAuthNotices = function(tids, hexname, callback){
		db.client.collection('semail').updateOne(
			{
				'_key': {'$regex': "^[tempauth:]+[0-9]+$"},
				'name':hexname,
				'delete':1,
				'tid':{'$in':tids}
			},
			{
				$set:{
					'notice': 1
				}
			},
			function(err,res){
				if(err) {
					return callback(err);
				}
				callback(null, res.result.nModified);
			}
		);
	};

	mymongodb.queryTemporaryAuthUnnotices = function(from, timestamp, limit, callback){
		var _now = Date.now();
		db.client.collection('semail').find(
			{
				'_key': {'$regex': "^[tempauth:]+[0-9]+$"},
				'delete':1,
				'notice':0,
				'name':from,
				'expire': (timestamp===0)?{'$gt': _now}:{'$lt': timestamp, '$gt':_now}
			},
			{
				'projection': {
					'_id': 0,
					'tid': 1,
					'message':1,
					'createdate':1
				}
			})
			.limit(limit)
			.sort({'expire': 1})
			.toArray(function (err, data) {
				if (err) {
					return callback(err);
				}
				if (data === null) {
					data = [];
				}
				callback(null, data);
			}
		);
	};

	mymongodb.temporaryAuth = function(from, content, callback){
		var timestamp = Date.now();
		var _data = {
			name:from,
			createdate:timestamp,
			expire: timestamp+86400000,
			content:content,
			delete:0,
			notice:0,
			signature:"",
			message:""
		};

		async.waterfall([
			function (next) {
				db.incrObjectField('global', 'semail_nextATid', next);
			},
			function (tid, next) {
				_data.tid = tid;
				db.client.collection('semail').updateOne(
					{
						_key: 'tempauth:' + tid
					},
					{
						$set:_data
					},
					{
						upsert: true,
						w: 1
					}, function(err){
						if(err) {
							return callback(err);
						}
						next(null, _data);
					}
				);
			}
		], callback);
	};

	mymongodb.removeAddressFromBlack = function(pubkey, from, callback){
		db.client.collection('semail').updateOne(
			{
				_key: 'black:' + from + ":to:" + pubkey,
				black:1
			},
			{
				$set:{
					actdate: Date.now(),
					black:0
				}
			},
			function(err,res){
				if(err) {
					return callback(err);
				}
				callback(null, res.result.nModified);
			}
		);
	};

	mymongodb.setAddressToBlack = function(pubkey, from, callback){
		db.client.collection('semail').updateOne(
			{
				_key: 'black:' + from + ":to:" + pubkey
			},
			{
				$set:{
					actdate: Date.now(),
					black:1
				}
			},
			{
				upsert: true,
				w: 1
			}, function(err){
				if(err) {
					return callback(err);
				}
				callback(null);
			}
		);
	};

	mymongodb.isBlackEmailAddress = function(pubkey, from, callback){
		db.client.collection('semail').findOne(
			{
				_key: 'black:' + from + ":to:" + pubkey,
				black:1
			},
			{
				'projection': {
					'_id': 0,
					'actdate': 1
				}
			},
			function(err,item){
				if (err) {
					return callback(err);
				}
				callback(null, item);
			}
		);
	};

	mymongodb.getUserBaseInfo = function (uid, bSelf, callback) {
		var _query = {
			'_id': 0,
			'nickname': 1,
			'gender':1,
			'info':1,
			'pics':1
		};

		if(bSelf === true){
			_query.upics = 1;
			_query.auth = 1;
			_query.coins = 1;
			_query.phone = 1;
		}

		db.client.collection('semail').findOne({_key: 'user:' + uid}, {"projection":_query}, function (err, item) {
			if (err) {
				return callback(err);
			}
			item = item || {};
			callback(null, item);
		});
	};

	mymongodb.getUidByUsername = function(username, callback) {
		if (!username) {
			return callback(null, null);
		}
		db.client.collection('semail').findOne({
			'_key': {'$regex': "^[user:]+[0-9]+$"},
			'name':username
		},
		{
			'projection': {
				'_id': 0,
				'uid': 1
			}
		},
		function(err, item){
			if (err) {
				return callback(err);
			}
			callback(null,item);
		});
	};
	
	mymongodb.updateUserFieldByUID = function(uid, setData, callback){
		callback = callback || function() {};
		db.client.collection('semail').updateOne({
			'_key': 'user:'+uid
		}, {$set: setData}, {
			upsert: true,
			w: 1
		}, function(err, res) {
			callback(err,res);
		});
	};

	mymongodb.createNewUser = function(username, ipaddress, callback){
		var timestamp = Date.now();
		var userData = {
			auth:-3,
			vids:[],
			upics:[],
			name:username,
			nickname:'',
			gender:-1,
			coins:0,
			phone:"",
			info:"",
			pics:[],
			regip:ipaddress,
			ip:ipaddress,
			joindate: timestamp,
			lastonline: timestamp
		};

		async.waterfall([
			function (next) {
				mymongodb.getUidByUsername(username, next);
			},
			function (exists, next) {
				if (exists) {
					return callback({error:"account-already-exists"});
				}
				db.incrObjectField('global', 'semail_nextUid', next);
			},
			function (uid, next) {
				userData.uid = uid;

				db.client.collection('semail').updateOne(
					{
						_key: 'user:' + uid
					},
					{
						$set:userData
					},
					{
						upsert: true,
						w: 1
					}, function(err){
						if(err) {
							return callback(err);
						}
						next(null, userData);
					}
				);
			}
		], callback);
	};

	mymongodb.getLeaveMessageCounts = function(to, from, callback){
		var _now = Date.now();
		db.client.collection('semail').countDocuments(
			{
				'_key': {'$regex': "^[mail:]+[0-9]+$"},
				'readed':0,
				'to':to,
				'from':from,
				'expire': {'$gt': _now}
			},
			function(err, count){
				count = parseInt(count, 10);
				callback(err, count || 0);
			}
		);
	};

	mymongodb.leaveMessage = function(to, from, content, signature, ipaddress, timestamp, callback){
		var _data = {
			content:content,
			to:to,
			from:from,
			sign:signature,
			ip:ipaddress,
			createdate:timestamp,
			expire: timestamp+86400000,
			readed:0
		};

		async.waterfall([
			function (next) {
				db.incrObjectField('global', 'semail_nextNid', next);
			},
			function (id, next) {
				_data.mid = id;

				db.client.collection('semail').updateOne(
					{
						_key: 'mail:' + id
					},
					{
						$set:_data
					},
					{
						upsert: true,
						w: 1
					}, function(err){
						if(err) {
							return callback(err);
						}
						next(null, id);
					}
				);
			}
		], callback);
	};

	mymongodb.deleteLeaveMessageByIDs = function(name, ids, callback){
		callback = callback || function() {};
		db.client.collection('semail').updateMany(
			{
				'_key': {'$regex': "^[mail:]+[0-9]+$"},
				'to':name,
				'readed':0,
				'mid':{'$in':ids}
			},
			{
				$set:{
					'readed':1
				}
			},
			function(err, res){
				if(err) {
					return callback(err);
				}
				callback(null, res.result.nModified);
			}
		);
	};
	
	mymongodb.getUnreadMessages = function(name, from, timestamp, limit, callback){
		var _now = Date.now();
		db.client.collection('semail').find(
			{
				'_key': {'$regex': "^[mail:]+[0-9]+$"},
				'readed':0,
				'to':name,
				'from':from,
				'expire': (timestamp===0)?{'$gt': _now}:{'$lt': timestamp, '$gt':_now}
			},
			{
				'projection': {
					'_id': 0,
					'mid': 1,
					'sign':1,
					'content':1,	
					'createdate':1
				}
			})
			.limit(limit)
			.sort({'expire': 1})
			.toArray(function (err, data) {
				if (err) {
					return callback(err);
				}
				if (data === null) {
					data = [];
				}
				callback(null, data);
			}
		);
	};


	mymongodb.getSortedSetRevRangeByScore = function (query, start, count, sort, fields, callback) {
		db.client.collection('objects').find(query, fields)
			.limit(count)
			.skip(start)
			.sort(sort)
			.toArray(function (err, data) {
				if (err) {
					return callback(err);
				}

				callback(null, data);
			});
	};

	mymongodb.queryNextArticleByTidAndPid = function (pid, tid, start, callback) {
		callback = callback || function() {};

		mymongodb.getSortedSetRevRangeByScore({
				'_key': {'$regex': "^[post:]+[0-9]+$"},
				'pid':  {$gt: pid},
				'tid':tid
			},
			start,
			1,
			{
				'pid': 1
			},
			{
				'projection': {
					'_id': 0,
					'content': 1,
					'pid': 1,
					'tid': 1,
					'timestamp': 1
				}
			},
			function (err, result) {
				if (err) {
					callback(err);
				} else {
					callback(null, result);
				}
			});
	};

	mymongodb.queryArticleByToPIDAndTID = function (toPid, tid, callback) {
		mymongodb.getSortedSetRevRangeByScore({
				'_key': {'$regex': "^[post:]+[0-9]+$"},
				'toPid': toPid.toString(),//{'$in':[toPid,toPid+""]},
				'tid':tid
			},
			0,
			1,
			{
				'pid': 1
			},
			{
				'projection': {
					'_id': 0,
					'content': 1,
					'pid': 1,
					'tid': 1,
					'timestamp': 1
				}
			},
			function (err, result) {
				if (err) {
					callback(err);
				} else {
					callback(null, result);
				}
			});
	};

	mymongodb.queryFourmArticle = function (mainPid, callback) {
		mymongodb.getSortedSetRevRangeByScore({
				'_key': "post:"+mainPid,
				'deleted':0
			},
			0,1,
			{'pid': 1},
			{
				'projection': {
					'_id': 0,
					'content': 1,
					'pid': 1,
					'tid': 1,
					'timestamp': 1
				}
			},
			function (err, result) {
				if (err) {
					callback(err);
				} else {
					callback(null, result);
				}
			});
	};

	mymongodb.queryPostFromFourmArticles = function(articles, nHtmlType, callback) {
		async.forEach(articles, function(item, eachcallback) {
			mymongodb.queryFourmArticle(item.mainPid,function(err,ret){
				if(err){
					return eachcallback(err);
				}
				if(ret.length>0) {
					if(nHtmlType === 2){
						var _jObj = _tryConvertStrToJson(ret[0].content);
						item.content = (_jObj === null) ? markdown.toHTML(ret[0].content) : ret[0].content;
					}else {
						item.content = (nHtmlType === 1) ? markdown.toHTML(ret[0].content) : ret[0].content;
					}
					item.timestamp = ret[0].timestamp;
					item.pid = ret[0].pid;
				}else{
					item.pid = 0;
				}
				eachcallback();
			});
		},function(err){
			if(err){
				return callback(err);
			}
			callback();
		});
	};

	mymongodb.queryHeadlinesArticles = function (cid, timestamp, bDeleted, bReverse, callback) {
		var _query = {
			'_key': {'$regex': "^[topic:]+[0-9]+$"},
			'cid': cid,
			'deleted':0,
			'timestamp': timestamp===0?{'$gt': timestamp}:{'$lt': timestamp}
		};
		if(bDeleted === true){
			delete _query.deleted;
		}
		mymongodb.getSortedSetRevRangeByScore(_query,
			0, 10,
			bReverse===true?{'timestamp': 1}:{'timestamp': -1},
			{
				'projection': {
					'_id': 0,
					'tid': 1,
					'title': 1,
					'mainPid': 1,
					//'locked':1,
					//'deleted':1,
					//'postcount':1,
					//'timestamp':1,
					'lastposttime': 1
				}
			},
			function (err, result) {
				if (err) {
					callback(err);
				} else {
					callback(null, result);
				}
			});
	};

}(exports));
