"use strict";
/**
 * 信鸽 Node SDK
 * @author huangnaiang
 * @version  
 * Copyright © 1998 - 2014 Tencent. All Rights Reserved. 腾讯公司 版权所有
 */

//引入相关模块
var http        = require('http');
var url         = require('url');
var util        = require('util');
var querystring = require('querystring');
var crypto      = require('crypto');

//定义api地址
var API_PUSH_TO_SINGLE_DEVICE      = 'http://openapi.xg.qq.com/v2/push/single_device';
var API_PUSH_TO_SINGLE_ACCOUNT     = 'http://openapi.xg.qq.com/v2/push/single_account';
var API_PUSH_BY_ACCOUNTS           = 'http://openapi.xg.qq.com/v2/push/account_list';
var API_PUSH_TO_ALL_DEVICES        = 'http://openapi.xg.qq.com/v2/push/all_device';
var API_PUSH_BY_TAGS               = 'http://openapi.xg.qq.com/v2/push/tags_device';
var API_QUERY_PUSH_STATUS          = 'http://openapi.xg.qq.com/v2/push/get_msg_status';
var API_QUERY_DEVICE_NUM           = 'http://openapi.xg.qq.com/v2/application/get_app_device_num';
var API_QUERY_TAGS                 = 'http://openapi.xg.qq.com/v2/tags/query_app_tags';
var API_CANCEL_TIMING_TASK         = 'http://openapi.xg.qq.com/v2/push/cancel_timing_task';
var API_SET_TAGS                   = 'http://openapi.xg.qq.com/v2/tags/batch_set';
var API_DELETE_TAGS                = 'http://openapi.xg.qq.com/v2/tags/batch_del';
var API_QUERY_TAGS_BY_DEVICE_TOKEN = 'http://openapi.xg.qq.com/v2/tags/query_token_tags';
var API_QUERY_DEVICE_NUM_BY_TAG    = 'http://openapi.xg.qq.com/v2/tags/query_tag_token_num';


/**
 * 一个实例代表一个信鸽app
 * @param {int} accessId  应用的唯一标识符，在提交应用时管理系统返回
 * @param {string} secretKey 应用的secret key，可在配置信息中查看
 */
function XingeApp(accessId, secretKey){

	//效验accessId是否为整形
	if(parseInt(accessId) !== accessId){
		throw new Error('accessId is invalid');
	}

	//效验secretKey是否为非空字符串
	if(typeof secretKey !== 'string' || secretKey.trim().length === 0){
		throw new Error('secretKey is invalid');
	}else{
		secretKey = secretKey.trim();
	}

	this.accessId  = accessId;
	this.secretKey = secretKey;

	/**
	 * 推送消息给单个设备
	 * @param {string}   deviceToken           设备token
	 * @param {Message}  message               推送的消息
     * @param {int}      environment           向iOS设备推送时必填，1表示推送生产环境；2表示推送开发环境。Android可不填。
	 * @param {Function} callback(err, result) 回调函数
	 */
	this.pushToSingleDevice = function(deviceToken, message, environment, callback){

		//效验deviceToken合法性
        deviceToken += '';
        deviceToken = deviceToken.trim();
		if(deviceToken.length === 0){
			throw new Error('deviceToken is invalid');
		}

		//效验message合法性
		if(!(message instanceof AndroidMessage) && !(message instanceof IOSMessage)){
			throw new Error('message is invalid');
		}

        //校验environment合法性
        if(message instanceof IOSMessage && environment !== exports.IOS_ENV_PRO && environment !== exports.IOS_ENV_DEV){
            throw new Error('environment is invalid');
        }

        if(message instanceof AndroidMessage && arguments.length === 3){
            callback = arguments[2];
        }

		//构造请求参数
		var params = {
			access_id: this.accessId,
			timestamp: Math.round((new Date()).getTime() / 1000),
			valid_time: 600,
			expire_time: message.expireTime,
			send_time: message.formatSendTime(),
			device_token: deviceToken,
			message: message.format()
		};

        //如果是Android平台,添加multi_pkg参数;如果是iOS平台，添加environment参数
        if(message instanceof AndroidMessage){
            params.message_type = message.type;
            params.multi_pkg = message.multiPkg;
        }else{
            params.message_type = 0;
            params.environment = environment;
        }

		//调用API
		callAPI(API_PUSH_TO_SINGLE_DEVICE, params, "POST", 10000, this.secretKey, callback);
	};

	/**
	 * 推送消息给单个账户或别名
	 * @param {string}   account               账户或别名
	 * @param {Message}  message               推送的消息
     * @param {int}      environment           向iOS设备推送时必填，1表示推送生产环境；2表示推送开发环境。Android可不填
	 * @param {Function} callback(err, result) 回调函数
     */
	this.pushToSingleAccount = function(account, message, environment, callback){

		//效验account是否为非空字符串
        account += '';
        account = account.trim();
		if(account.length === 0){
			throw new Error('account is invalid');
		}

		//效验message
		if(!(message instanceof AndroidMessage) && !(message instanceof IOSMessage)){
			throw new Error('message is invalid');
		}

        //校验environment合法性
        if(message instanceof IOSMessage && environment !== exports.IOS_ENV_PRO && environment !== exports.IOS_ENV_DEV){
            throw new Error('environment is invalid');
        }

        if(message instanceof AndroidMessage && arguments.length === 3){
            callback = arguments[2];
        }

		//构造请求参数
		var params = {
			access_id: this.accessId,
			timestamp: Math.round((new Date()).getTime() / 1000),
			valid_time: 600,
			expire_time: message.expireTime,
			send_time: message.formatSendTime(),
			account: account,
			message: message.format()
		};

        //如果是Android平台,添加multi_pkg参数;如果是iOS平台，添加environment参数
        if(message instanceof AndroidMessage){
            params.message_type = message.type;
            params.multi_pkg = message.multiPkg;
        }else{
            params.message_type = 0;
            params.environment = environment;
        }

		//调用API
		callAPI(API_PUSH_TO_SINGLE_ACCOUNT, params, "POST", 10000, this.secretKey, callback);

	};

	/**
	 * 推送消息给批量账号
	 * @param {array}    accounts    账号数组
	 * @param {Message}  message     推送的消息
	 * @param {int}      environment 向iOS设备推送时必填，1表示推送生产环境；2表示推送开发环境。Android可不填
	 * @param {Function} callback    回调函数
	 */
	this.pushByAccounts = function(accounts, message, environment, callback){

		//效验accounts
		if(!util.isArray(accounts) || accounts.length === 0){
			throw new Error('accounts is invalid');
		}else{
			for(var i=0; i < accounts.length; i++){
				accounts[i] += '';
				accounts[i] = accounts[i].trim();
				if(accounts[i].length === 0){
					throw new Error('accounts is invalid');
				}
			}
		}

		//效验message
		if(!(message instanceof AndroidMessage) && !(message instanceof IOSMessage)){
			throw new Error('message is invalid');
		}

		//校验environment
		if(message instanceof IOSMessage && environment !== exports.IOS_ENV_PRO && environment !== exports.IOS_ENV_DEV){
			throw new Error('environment is invalid');
		}

		if(message instanceof AndroidMessage && arguments.length === 3){
			callback = arguments[2];
		}

		//构造请求参数
		var params = {
			access_id: this.accessId,
			timestamp: Math.round((new Date()).getTime() / 1000),
			valid_time: 600,
			expire_time: message.expireTime,
			account_list: JSON.stringify(accounts),
			message: message.format()
		};

		//如果是Android平台,添加multi_pkg参数;如果是iOS平台，添加environment参数
		if(message instanceof AndroidMessage){
			params.message_type = message.type;
			params.multi_pkg = message.multiPkg;
		}else{
			params.message_type = 0;
			params.environment = environment;
		}

		//调用API
		callAPI(API_PUSH_BY_ACCOUNTS, params, "POST", 10000, this.secretKey, callback);

	};

	/**
	 * 推送消息到所有设备
	 * @param {Message}  message               推送的消息
     * @param {int}      environment           向iOS设备推送时必填，1表示推送生产环境；2表示推送开发环境。Android可不填
	 * @param {Function} callback(err, result) 回调函数
     */
	this.pushToAllDevices = function(message, environment, callback){

		//效验message
		if(!(message instanceof AndroidMessage) && !(message instanceof IOSMessage)){
			throw new Error('message is invalid');
		}

        //校验environment
        if(message instanceof IOSMessage && environment !== exports.IOS_ENV_PRO && environment !== exports.IOS_ENV_DEV){
            throw new Error('environment is invalid');
        }

        if(message instanceof AndroidMessage && arguments.length === 2){
            callback = arguments[1];
        }

		//构造请求参数
		var params = {
			access_id: this.accessId,
			timestamp: Math.round((new Date()).getTime() / 1000),
			valid_time: 600,
			expire_time: message.expireTime,
			send_time: message.formatSendTime(),
			message: message.format()
		};

        //重复推送
        if(parseInt(message.loopTimes) === message.loopTimes && parseInt(message.loopInterval) === message.loopInterval){
            params.loop_times    = parseInt(message.loopTimes);
            params.loop_interval = parseInt(message.loopInterval);
        }

        //如果是Android平台,添加multi_pkg参数;如果是iOS平台，添加environment参数
        if(message instanceof AndroidMessage){
            params.message_type = message.type;
            params.multi_pkg = message.multiPkg;
        }else{
            params.message_type = 0;
            params.environment = environment;
        }

		//调用API
		callAPI(API_PUSH_TO_ALL_DEVICES, params, "POST", 10000, this.secretKey, callback);

	};

	/**
	 * 根据指定的tag推送消息
	 * @param {array}    tags                  指定推送目标的tag列表，每个tag是一个string
	 * @param {string}   tagOperation          多个tag的运算关系，取值为AND或OR
	 * @param {Message}  message               推送的消息
     * @param {int}      environment           向iOS设备推送时必填，1表示推送生产环境；2表示推送开发环境。Android可不填
	 * @param {Function} callback(err, result) 回调函数
     */
	this.pushByTags = function(tags, tagOperation, message, environment, callback){

		//效验tags
		if(!util.isArray(tags) || tags.length === 0){
			throw new Error('tags is invalid');
		}else{
			for(var i=0; i < tags.length; i++){
                tags[i] += '';
                tags[i] = tags[i].trim();
				if(tags[i].length === 0){
					throw new Error('tags is invalid');
				}
			}
		}

		//效验tagOperation
		if(tagOperation !== exports.TAG_OPERATION_AND && tagOperation !== exports.TAG_OPERATION_OR){
			throw new Error('tagOperation is invalid');
		}

        //效验message
        if(!(message instanceof AndroidMessage) && !(message instanceof IOSMessage)){
            throw new Error('message is invalid');
        }

        //校验environment
        if(message instanceof IOSMessage && environment !== exports.IOS_ENV_PRO && environment !== exports.IOS_ENV_DEV){
            throw new Error('environment is invalid');
        }

        if(message instanceof AndroidMessage && arguments.length === 4){
            callback = arguments[3];
        }

		//构造请求参数
		var params = {
			access_id: this.accessId,
			timestamp: Math.round((new Date()).getTime() / 1000),
			valid_time: 600,
			expire_time: message.expireTime,
			send_time: message.formatSendTime(),
			tags_list: JSON.stringify(tags),
			tags_op: tagOperation,
			message: message.format()
		};

        //重复推送
        if(parseInt(message.loopTimes) === message.loopTimes && parseInt(message.loopInterval) === message.loopInterval){
            params.loop_times    = parseInt(message.loopTimes);
            params.loop_interval = parseInt(message.loopInterval);
        }

        //如果是Android平台,添加multi_pkg参数;如果是iOS平台，添加environment参数
        if(message instanceof AndroidMessage){
            params.message_type = message.type;
            params.multi_pkg = message.multiPkg;
        }else{
            params.message_type = 0;
            params.environment = environment;
        }

		//调用API
		callAPI(API_PUSH_BY_TAGS, params, "POST", 10000, this.secretKey, callback);

	};

	/**
	 * 批量查询推送状态
	 * @param {array}    pushIds               推送id数组
	 * @param {Function} callback(err, result) 回调函数
	 */
	this.queryPushStatus = function(pushIds, callback){

		var arrPushIds = [];

		if(!util.isArray(pushIds) || pushIds.length === 0){
			throw new Error('pushIds is invalid');
		}else{
			for(var i=0; i<pushIds.length; i++){
				var pushId = pushIds[i] + '';
                pushId = pushId.trim();
				if(pushId.length === 0){
					throw new Error('pushIds is invalid');
				}else{
					arrPushIds.push({'push_id': pushId});
				}
			}		
		}

		//构造请求参数
		var params = {
			access_id: this.accessId,
			timestamp: Math.round((new Date()).getTime() / 1000),
			valid_time: 600,
			push_ids: JSON.stringify(arrPushIds)
		};

		//调用API
		callAPI(API_QUERY_PUSH_STATUS, params, "POST", 10000, this.secretKey, callback);

	};

	/**
	 * 查询设备数
	 * @param {Function} callback(err, result) 回调函数
	 */
	this.queryDeviceNum = function(callback){

		//构造查询参数
		var params = {
			access_id: this.accessId,
			timestamp: Math.round((new Date()).getTime() / 1000),
			valid_time: 600
		};

		//调用API
		callAPI(API_QUERY_DEVICE_NUM, params, "POST", 10000, this.secretKey, callback);

	};

	/**
	 * 查询应用标签
	 * @param {int}      start                 开始位置
	 * @param {int}      limit                 查询数量
	 * @param {int}      validTime             配合timestamp确定请求的有效期，单位为秒，最大值为600，默认值600
	 * @param {Function} callback(err, result) 回调函数
	 */
	this.queryTags = function(start, limit, callback){

		//效验start
		if(parseInt(start) !== start || start < 0){
			start = 0;
		}

		//效验limit
		if(parseInt(limit) !== limit || limit < 1){
			limit = 100;
		}

		//构造查询参数
		var params = {
			access_id: this.accessId,
			timestamp: Math.round((new Date()).getTime() / 1000),
			valid_time: 600,
			start: start,
			limit: limit
		};

		//调用API
		callAPI(API_QUERY_TAGS, params, "POST", 10000, this.secretKey, callback);

	};

	/**
	 * 取消尚未触发的定时推送任务
	 * @param {int}      pushId                消息推送id
	 * @param {Function} callback(err, result) 回调函数
	 */
	this.cancelTimingTask = function(pushId, callback){

		//效验pushId
        pushId += '';
        pushId = pushId.trim();
		if(pushId.length === 0){
			throw new Error('pushId is invalid');
		}

		//构造查询参数
		var params = {
			access_id: this.accessId,
			timestamp: Math.round((new Date()).getTime() / 1000),
			valid_time: 600,
			push_id: pushId
		};

		//调用API
		callAPI(API_CANCEL_TIMING_TASK, params, "POST", 10000, this.secretKey, callback);

	};

    /**
     * 批量为token设置标签
     * @param {array}    tagsTokensMap         tag和token的二维数组，每次最多设置20对。如：[['tag1', 'token1'], ['tag2', 'token2']]。
     * @param {Function} callback(err, result) 回调函数
     */
    this.setTags = function(tagsTokensMap, callback){

        var isTagsTokensMapValid = true;

        //校验tagsTokensMap
        if(!util.isArray(tagsTokensMap) || tagsTokensMap.length < 1 || tagsTokensMap.length > 20){
            isTagsTokensMapValid = false;
        }else{
            for(var i = 0; i < tagsTokensMap.length; i++){
                if(!util.isArray(tagsTokensMap[i]) || tagsTokensMap[i].length !== 2){
                    isTagsTokensMapValid = false;
                    break;
                }else{

                    tagsTokensMap[i][0] += '';
                    tagsTokensMap[i][0] = tagsTokensMap[i][0].trim();

                    tagsTokensMap[i][1] += '';
                    tagsTokensMap[i][1] = tagsTokensMap[i][1].trim();

                    if(tagsTokensMap[i][0].length === 0 || tagsTokensMap[i][1] === 0){
                        isTagsTokensMapValid = false;
                        break;
                    }

                }
            }
        }

        if(!isTagsTokensMapValid){
            throw new Error('tagsTokensMap is invalid');
        }

        //构造查询参数
        var params = {
            access_id: this.accessId,
            timestamp: Math.round((new Date()).getTime() / 1000),
            valid_time: 600,
            tag_token_list: JSON.stringify(tagsTokensMap)
        };

        //调用API
        callAPI(API_SET_TAGS, params, "POST", 10000, this.secretKey, callback);

    };

    /**
     * 批量为token删除标签
     * @param {array}    tagsTokensMap         tag和token的二维数组，每次最多设置20对。如：[['tag1', 'token1'], ['tag2', 'token2']]。
     * @param {Function} callback(err, result) 回调函数
     */
    this.deleteTags = function(tagsTokensMap, callback){

        var isTagsTokensMapValid = true;

        //校验tagsTokensMap
        if(!util.isArray(tagsTokensMap) || tagsTokensMap.length < 1 || tagsTokensMap.length > 20){
            isTagsTokensMapValid = false;
        }else{
            for(var i = 0; i < tagsTokensMap.length; i++){
                if(!util.isArray(tagsTokensMap[i]) || tagsTokensMap[i].length !== 2){
                    isTagsTokensMapValid = false;
                    break;
                }else{

                    tagsTokensMap[i][0] += '';
                    tagsTokensMap[i][0] = tagsTokensMap[i][0].trim();

                    tagsTokensMap[i][1] += '';
                    tagsTokensMap[i][1] = tagsTokensMap[i][1].trim();

                    if(tagsTokensMap[i][0].length === 0 || tagsTokensMap[i][1] === 0){
                        isTagsTokensMapValid = false;
                        break;
                    }

                }
            }
        }

        if(!isTagsTokensMapValid){
            throw new Error('tagsTokensMap is invalid');
        }

        //构造查询参数
        var params = {
            access_id: this.accessId,
            timestamp: Math.round((new Date()).getTime() / 1000),
            valid_time: 600,
            tag_token_list: JSON.stringify(tagsTokensMap)
        };

        //调用API
        callAPI(API_DELETE_TAGS, params, "POST", 10000, this.secretKey, callback);

    };

    /**
     * 根据设备token查询标签
     * @param {string}   deviceToken 设备token
     * @param {function} callback    回调函数
     */
    this.queryTagsByDeviceToken = function(deviceToken, callback){

        //校验token
        deviceToken += '';
        deviceToken = deviceToken.trim();

        if(deviceToken.length === 0){
            throw new Error('deviceToken is invalid');
        }

        //构造查询参数
        var params = {
            access_id: this.accessId,
            timestamp: Math.round((new Date()).getTime() / 1000),
            valid_time: 600,
            device_token: deviceToken
        };

        //调用API
        callAPI(API_QUERY_TAGS_BY_DEVICE_TOKEN, params, "POST", 10000, this.secretKey, callback);
    };

    /**
     * 根据标签查询设备数
     * @param {string}   tag      标签
     * @param {function} callback 回调函数
     */
    this.queryDeviceNumByTag = function(tag, callback){

        //校验tag
        tag += '';
        tag = tag.trim();

        if(tag.length === 0){
            throw new Error('tag is invalid');
        }

        //构造查询参数
        var params = {
            access_id: this.accessId,
            timestamp: Math.round((new Date()).getTime() / 1000),
            valid_time: 600,
            tag: tag
        };

        //调用API
        callAPI(API_QUERY_DEVICE_NUM_BY_TAG, params, "POST", 10000, this.secretKey, callback);
    };


}

/**
 * android消息类
 */
function AndroidMessage(){

	//标题，必须为字符串
	this.title = '';
	//内容，必须为字符串
	this.content = '';
	//类型，通知或消息，必须为Message.MESSAGE_TYPE_NOTIFICATION或Message.MESSAGE_TYPE_MESSAGE
	this.type = null;
	//消息离线存储时间，单位为秒，必须为整形，默认不存储, 最长为3天
	this.expireTime = 0;
	//推送时间的时间戳，单位为秒，必须为整形，如果小于当前时间戳则立即发送；如果是重复推送，则代表重复推送起始时间
	this.sendTime = 0;
	//自定义的key:value参数，
	this.customContent = {};
	//允许推送给用户的时段，每个元素必须是TimeInterval的实例
	this.acceptTime = [];
	//消息风格，必须为Style的实例，仅对通知有效
	this.style = null;
	//点击动作，必须为ClickAction的实例，仅对通知有效
	this.action = null;
	//0表示按注册时提供的包名分发消息；1表示按access id分发消息，所有以该access id成功注册推送的app均可收到消息。本字段对iOS平台无效
	this.multiPkg = 0;
    //重复推送的次数
    this.loopTimes = null;
    //重复推送的时间间隔，单位为天
    this.loopInterval = null;

	/**
	 * 格式化sendTime
	 * @return {string} YYYY-MM-DD hh:mm:ss格式的sendTime
	 */
	this.formatSendTime = function(){

		var dateSendTime = new Date();
		dateSendTime.setTime(this.sendTime * 1000);
		
		var year = dateSendTime.getFullYear();
		
		var month = dateSendTime.getMonth() + 1;
		(month < 10) && (month = '0' + month);

		var day = dateSendTime.getDate();
		(day < 10) && (day = '0' + day);

		var hour = dateSendTime.getHours();
		(hour < 10) && (hour = '0' + hour);

		var minute = dateSendTime.getMinutes();
		(minute < 10) && (minute = '0' + minute);

		var second = dateSendTime.getSeconds();
		(second < 10) && (second = '0' + second);
		
		return year + '-' + month + '-' + day + ' ' + hour + ':' + minute + ':' + second;
	};

	/**
	 * 格式化message
	 * @return {string} 格式化后的message
	 */
	this.format = function(){

        isAndroidMessageValid(this);

		var mess = {
			content: this.content
		};

		if(this.title.trim().length > 0){
			mess.title = this.title;
		}

		if(!isEmptyObj(this.customContent)){
			mess.custom_content = this.customContent;
		}

		if(this.acceptTime.length > 0){
			mess.accept_time = this.acceptTime;
		}

		if(this.type === exports.MESSAGE_TYPE_NOTIFICATION){

            mess.ring       = this.style.ring;
            mess.ring_raw   = this.style.ringRaw;
            mess.vibrate    = this.style.vibrate;
            mess.lights     = this.style.lights;
            mess.small_icon = this.style.smallIcon;
            mess.icon_type  = this.style.iconType;
            mess.icon_res   = this.style.iconRes;
			mess.builder_id = this.style.builderId;
            mess.style_id   = this.style.styleId;
			mess.clearable  = this.style.clearable;
			mess.n_id       = this.style.nId;

			mess.action = this.action.format();
		}

		return JSON.stringify(mess);

	}

	
}

/**
 * iOS消息类
 */
function IOSMessage(){

    //消息离线存储时间，单位为秒，必须为整形，默认不存储, 最长为3天
    this.expireTime = 0;
    //推送时间的时间戳，单位为秒，必须为整形，如果小于当前时间戳则立即发送；如果是重复推送，则代表重复推送起始时间
    this.sendTime = 0;
    //自定义的key:value参数，
    this.customContent = {};
    //允许推送给用户的时段，每个元素必须是TimeInterval的实例
    this.acceptTime = [];
    //定义详见APNS payload中的alert字段
    this.alert;
    //整形或null，设置角标数值。定义详见APNS payload中的badge字段
    this.badge = null;
    //设置通知声音。定义详见APNS payload中的sound字段
    this.sound = null;
    //重复推送的次数
    this.loopTimes = null;
    //重复推送的时间间隔，单位为天
    this.loopInterval = null;


    /**
     * 格式化sendTime
     * @return {string} YYYY-MM-DD hh:mm:ss格式的sendTime
     */
    this.formatSendTime = function(){

        var dateSendTime = new Date();
        dateSendTime.setTime(this.sendTime * 1000);

        var year = dateSendTime.getFullYear();

        var month = dateSendTime.getMonth() + 1;
        (month < 10) && (month = '0' + month);

        var day = dateSendTime.getDate();
        (day < 10) && (day = '0' + day);

        var hour = dateSendTime.getHours();
        (hour < 10) && (hour = '0' + hour);

        var minute = dateSendTime.getMinutes();
        (minute < 10) && (minute = '0' + minute);

        var second = dateSendTime.getSeconds();
        (second < 10) && (second = '0' + second);

        return year + '-' + month + '-' + day + ' ' + hour + ':' + minute + ':' + second;
    };

    /**
     * 格式化message
     * @return {string} 格式化后的message
     */
    this.format = function(){

        isIOSMessageValid(this);

        var aps = {
            alert: this.alert
        };

        if(parseInt(this.badge) === this.badge){
            aps.badge = this.badge;
        }

        if(typeof this.sound === 'string'){
            aps.sound = this.sound;
        }

        var mess = this.customContent;

        if(this.acceptTime.length > 0){
            mess.accept_time = this.acceptTime;
        }

        mess.aps = aps;

        return JSON.stringify(mess);

    }


}


/**
 * 表示一个允许推送的时间闭区间，从startHour：startMin到endHour：endMin
 * @param {int} startHour 开始小时
 * @param {int} startMin  开始分钟
 * @param {int} endHour   结束小时
 * @param {int} endMin    结束分钟
 */
function TimeInterval(startHour, startMin, endHour, endMin){

	this.start = {
		hour: null,
		min: null
	};
	this.end = {
		hour: null,
		min: null
	};

	//效验时间合法性
	if(parseInt(startHour) !== startHour || startHour < 0 || startHour > 23 || 
		parseInt(startMin) !== startMin || startMin < 0 || startMin > 59 || 
		parseInt(endHour) !== endHour || endHour < 0 || endHour > 23 || 
		parseInt(endMin) !== endMin || endMin < 0 || endMin > 59){

		throw new Error('startHour or startMin or endHour or endMin is invalid');
	}

	this.start.hour = startHour + '';
	this.start.min  = startMin + '';
	this.end.hour   = endHour + '';
	this.end.min    = endMin + '';

}

/**
 * 定义消息的展示风格
 */
function Style(){

    //是否响铃
    this.ring = 1;
    //铃声文件，为空则是默认铃声
    this.ringRaw = '';
    //是否振动
    this.vibrate = 1;
    //是否呼吸灯
    this.lights = 1;
    //状态栏图标文件，为空则是app icon
    this.smallIcon = '';
    //通知栏图标文件类型，0是本地文件，1是网络图片
    this.iconType = 0;
    //通知栏图片地址，可填本地文件名或图片http地址，为空则是app icon
    this.iconRes = '';
    //本地通知样式，含义参见终端SDK文档
    this.builderId = 0;
    //样式表优先级，当样式表与推送样式冲突时，0表示以新设置的推送样式为准，1表示以样式表为准
    this.styleId = 1;
    //通知栏是否可清除，0否，1是
	this.clearable = 1;
    //是否覆盖历史通知。大于0则会覆盖先前弹出的相同id通知，为0展示本条通知且不影响其他通知，为-1将清除先前弹出的所有通知，仅展示本条通知
	this.nId = 0;

}

/**
 * 通知消息被点击时触发的事件
 */
function ClickAction(){

    /*
     点击后的动作
     exports.ACTION_TYPE_ACTIVITY     打开Activity或APP
     exports.ACTION_TYPE_BROWSER      打开浏览器
     exports.ACTION_TYPE_INTENT       打开intent
     exports.ACTION_TYPE_PACKAGE_NAME 通过包名打开应用
     */
    this.actionType = exports.ACTION_TYPE_ACTIVITY;

    //要打开的app或者activity,当actionType ＝ ACTION_TYPE_ACTIVITY生效
    this.activity = '';
    //当actionType ＝ ACTION_TYPE_ACTIVITY生效
    this.atyAttr = {
        //创建通知时，intent的属性，如：intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED);
        if: '',
        //PendingIntent的属性，如：PendingIntent.FLAG_UPDATE_CURRENT
        pf: ''
    };

    //当actionType ＝ ACTION_TYPE_BROWSER生效
    this.browser = {
        //要打开的url
        url: '',
        //是否需要用户确认，0为否，1为是
        confirm: 0
    };

    //要打开的intent,当actionType ＝ ACTION_TYPE_INTENT生效
    this.intent = '';

    //当actionType ＝ ACTION_TYPE_PACKAGE_NAME生效
    this.packageName = {
        //packageName：app应用拉起别的应用的包名
        packageName: '',
        //拉起应用的下载链接，若客户端没有找到此应用会自动去下载
        packageDownloadUrl: '',
        //是否需要用户确认，0为否，1为是
        confirm: 0
    };

    this.format = function(){

        var action = {
            action_type: this.actionType
        };

        switch (action.action_type){
            default:
            case exports.ACTION_TYPE_ACTIVITY:
                if(this.activity.trim() !== ''){
                    action.activity = this.activity.trim();
                }
                if(this.atyAttr.if.trim() !== '' || this.atyAttr.pf.trim() !== ''){
                    action.aty_attr = {
                        if: this.atyAttr.if.trim(),
                        pf: this.atyAttr.pf.trim()
                    };
                }
                break;
            case exports.ACTION_TYPE_BROWSER:
                if(this.browser.url.trim() !== ''){
                    action.browser = {
                        url: this.browser.url.trim(),
                        confirm: parseInt(this.browser.confirm)
                    };
                }
                break;
            case exports.ACTION_TYPE_INTENT:
                if(this.intent.trim() !== ''){
                    action.intent = this.intent.trim();
                }
                break;
            case exports.ACTION_TYPE_PACKAGE_NAME:
                if(this.packageName.packageName.trim() !== ''){
                    action.package_name = {
                        packageName: this.packageName.packageName.trim(),
                        packageDownloadUrl: this.packageName.packageDownloadUrl.trim(),
                        confirm: parseInt(this.packageName.confirm)
                    };
                }
                break;
        };

        return action;
    };

}

/**
 * 检查AndroidMessage对象是否合法
 * @param  {[type]}  message 待检查的message对象
 * @return {Boolean}         检查结果
 */
function isAndroidMessageValid(message){

	if(!(message instanceof AndroidMessage)){
		throw new Error('message is invalid');
	}

	if(typeof message.content !== 'string' || message.content.trim().length === 0){
		throw new Error('content is invalid');
	}

	if(message.type !== exports.MESSAGE_TYPE_NOTIFICATION && message.type !== exports.MESSAGE_TYPE_MESSAGE){
		throw new Error('type is invalid');
	}

	if(parseInt(message.expireTime) !== message.expireTime || message.expireTime < 0 || message.expireTime > 60*60*24*3){
		throw new Error('expireTime is invalid');
	}

	if(parseInt(message.sendTime) !== message.sendTime || message.sendTime < 0){
		throw new Error('sendTime is invalid');
	}

	if(!isAndroidCustomContentValid(message.customContent)){
		throw new Error('customContent is invalid');
	}

	if(!isAccessTimeValid(message.acceptTime)){
		throw new Error('acceptTime is invalid');
	}

    if(message.multiPkg !== 0 && message.multiPkg !== 1){
        throw new Error('multiPkg is invalid');
    }

    if(message.loopTimes !== null && parseInt(message.loopTimes) !== message.loopTimes){
        throw new Error('loopTimes is invalid');
    }

    if(message.loopInterval !== null && parseInt(message.loopInterval) !== message.loopInterval){
        throw new Error('loopInterval is invalid');
    }

	if(message.type === exports.MESSAGE_TYPE_NOTIFICATION){
		
		//效验通知合法性
		
		if(typeof message.title !== 'string' || message.title.trim().length === 0){
			throw new Error('title is invalid');
		}

        isStyleValid(message.style);

        isActionValid(message.action);

	}else{

		//效验消息合法性
		if(typeof message.title !== 'string'){
			throw new Error('title is invalid');
		}		
	}

	return true;
}

/**
 *
 * 校验AndroidMessage对象的action属性是否合法
 * @param action
 */
function isActionValid(action){

    if(!(action instanceof ClickAction)){
        throw new Error('action is invalid');
    }

	if(action.actionType !== exports.ACTION_TYPE_ACTIVITY && action.actionType !== exports.ACTION_TYPE_BROWSER &&
		action.actionType !== exports.ACTION_TYPE_INTENT && action.actionType !== exports.ACTION_TYPE_PACKAGE_NAME){

        throw new Error('action.actionType is invalid');
    }
}

/**
 * 校验AndroidMessage对象的style属性是否合法
 * @param style
 */
function isStyleValid(style){

    if(!(style instanceof Style)){
        throw new Error('style is invalid');
    }

    if(parseInt(style.ring) !== 0 && parseInt(style.ring) !== 1){
        throw new Error('style.ring is invalid');
    }

    if(parseInt(style.vibrate) !== 0 && parseInt(style.vibrate) !== 1){
        throw new Error('style.vibrate is invalid');
    }

    if(parseInt(style.lights) !== 0 && parseInt(style.lights) !== 1){
        throw new Error('style.lights is invalid');
    }

    if(parseInt(style.iconType) !== 0 && parseInt(style.iconType) !== 1){
        throw new Error('style.iconType is invalid');
    }

    if(parseInt(style.builderId) !== style.builderId){
        throw new Error('style.builderId is invalid');
    }

    if(parseInt(style.styleId) !== 0 && parseInt(style.styleId) !== 1){
        throw new Error('style.styleId is invalid');
    }

    if(parseInt(style.clearable) !== 0 && parseInt(style.clearable) !== 1){
        throw new Error('style.clearable is invalid');
    }

    if(parseInt(style.nId) !== style.nId || style.nId < -1){
        throw new Error('style.nId is invalid');
    }

}


/**
 * 检查IOSMessage对象是否合法
 * @param  {[type]}  message 待检查的message对象
 * @return {Boolean}         检查结果
 */
function isIOSMessageValid(message){

    if(!(message instanceof IOSMessage)){
        throw new Error('message is invalid');
    }

    if(parseInt(message.expireTime) !== message.expireTime || message.expireTime < 0 || message.expireTime > 60*60*24*3){
        throw new Error('expireTime is invalid');
    }

    if(parseInt(message.sendTime) !== message.sendTime || message.sendTime < 0){
        throw new Error('sendTime is invalid');
    }

    if(!isIOSCustomContentValid(message.customContent)){
        throw new Error('customContent is invalid');
    }

    if(!isAccessTimeValid(message.acceptTime)){
        throw new Error('acceptTime is invalid');
    }

    if(typeof message.alert !== 'string' && typeof message.alert !== 'object'){
        throw new Error('alert is invalid');
    }

    if((message.badge !== null) && (parseInt(message.badge) !== message.badge)){
        throw new Error('badge is invalid');
    }

    if((message.sound !== null ) && (typeof message.sound !== 'string')){
        throw new Error('sound is invalid');
    }

    if(message.loopTimes !== null && parseInt(message.loopTimes) !== message.loopTimes){
        throw new Error('loopTimes is invalid');
    }

    if(message.loopInterval !== null && parseInt(message.loopInterval) !== message.loopInterval){
        throw new Error('loopInterval is invalid');
    }

    return true;
}


/**
 * 检查acceptTime是否合法
 * @param  {array} acceptTime 待检查的acceptTime数组
 * @return {Boolean}          检查结果
 */
function isAccessTimeValid(acceptTime){

	var isValid = true;

	if(!util.isArray(acceptTime)){
		isValid = false;
	}else{
		for(var i=0; i < acceptTime.length; i++){
			if(!(acceptTime[i] instanceof TimeInterval)){
				isValid = false;
				break;
			}
		}
	}

	return isValid;
}

/**
 * 检查customContent是否合法
 * @param  {object} customContent 待检查的customContent对象
 * @return {Boolean}              检查结果
 */
function isAndroidCustomContentValid(customContent){

	var isValid = true;

	if(typeof customContent !== 'object'){
		isValid = false;
	}else{
		for(var key in customContent){
			if(typeof customContent[key] !== 'string'){
				isValid = false;
				break;
			}
		}
	}

	return isValid;
}

/**
 * 检查customContent是否合法
 * @param  {object} customContent 待检查的customContent对象
 * @return {Boolean}              检查结果
 */
function isIOSCustomContentValid(customContent){

    var isValid = true;

    if(typeof customContent !== 'object'){
        isValid = false;
    }

    return isValid;
}

/**
 * 调用API
 * @param  {string}   api                   api地址
 * @param  {object}   params                参数对象
 * @param  {string}   method                请求方法，GET或POST
 * @param  {int}      timeout               超时时间，单位毫秒
 * @param  {string}   secretKey             应用的secretKey
 * @param  {Function} callback(err, result) 回调函数
 */
function callAPI(api, params, method, timeout, secretKey, callback){
	var requestOption, strParams;
	try{
		//将method转为大写
		method = method.toUpperCase();
		//效验method
		if(method !== 'GET' && method !== 'POST'){
			throw new Error('method is invalid');
		}

        //效验timeout
        if(parseInt(timeout) !== timeout || timeout < 1){
            timeout = 3000;
        }
		
		//生成sign
		params.sign = generateSign(api, params, method, secretKey);
		strParams = querystring.stringify(params);

		var urlParams = url.parse(api);
		var host = urlParams.host;
		var path = urlParams.path;

		if(method === 'GET'){
			path += '?' + strParams;
		}

		requestOption = {
			host: host,
			path: path,
			method: method,
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8'
			}
		};

		if(method === 'POST'){
			requestOption.headers['Content-Length'] = strParams.length;
		}

	}catch(e){
		return typeof callback === 'function' && callback(e);
	}

	var req = http.request(requestOption, function(res){
		res.setEncoding('utf8');
		res.on('data', function(data){
			typeof callback === 'function' && callback(null, data);
		});
	});

	req.on('error', function(e){
		typeof callback === 'function' && callback(e);
	});

	if(method === 'POST'){
		req.write(strParams);
	}

    req.setTimeout(timeout, function(){
        req.abort();
    });

	req.end();
}

/**
 * 生成sign
 * @param  {string} api       api地址
 * @param  {object} params    参数对象
 * @param  {string} method    请求方法，GET或POST
 * @param  {string} secretKey 应用的secretKey
 * @return {string}           生成的sign
 */
function generateSign(api, params, method, secretKey){

	//将method转为大写
	method = method.toUpperCase();
	if(method !== 'GET' && method !== 'POST'){
		throw new Error('method is invalid');
	}

	if(typeof params !== 'object'){
		throw new Error('params is invalid');
	}

	//提取host和path
	var urlParams = url.parse(api);
	var hostPath  = urlParams.host + urlParams.path;

	//对params里的key进行排序
	var arrKey = [];
	for(var key in params){
		arrKey.push(key);
	}
	arrKey.sort();

	//拼接参数字符串
	var strParams = '';
	for(var i=0; i < arrKey.length; i++){
		var value = params[arrKey[i]];
		strParams += arrKey[i] + '=' + value;
	}

	return md5(method + hostPath + strParams + secretKey);
}

/**
 * 检查是否空对象
 * @param  {object}  obj 待检查对象
 * @return {Boolean}     检查结果
 */
function isEmptyObj(obj){
	if(typeof obj !== 'object'){
		return false;
	}else{
		for(var attr in obj){
			return false;
		}
		return true;
	}
}

/**
 * md5加密
 * @param  {string} str 需要进行加密的字符串
 * @return {string}     加密后的字符串
 */
function md5(str){
	if(typeof str !== 'string'){
		return false;
	}
	return crypto.createHash('md5').update(str, 'utf8').digest('hex');
}

//导出模块


//-------常量定义 start---------


//消息类型：通知
exports.MESSAGE_TYPE_NOTIFICATION = 1;
//消息类型：透传消息
exports.MESSAGE_TYPE_MESSAGE      = 2;


//消息推送适配平台：不限
exports.DEVICE_TYPE_ALL      = 0;
//消息推送适配平台：浏览器
exports.DEVICE_TYPE_BROWSER  = 1;
//消息推送适配平台：PC
exports.DEVICE_TYPE_PC       = 2;
//消息推送适配平台：Android
exports.DEVICE_TYPE_ANDROID  = 3;
//消息推送适配平台：iOS
exports.DEVICE_TYPE_IOS      = 4;
//消息推送适配平台：winPhone
exports.DEVICE_TYPE_WINPHONE = 5;


//tag运算关系：AND
exports.TAG_OPERATION_AND = 'AND';
//tag运算关系：OR
exports.TAG_OPERATION_OR  = 'OR';


//点击动作：打开Activity或APP
exports.ACTION_TYPE_ACTIVITY     = 1;
//点击动作：打开浏览器
exports.ACTION_TYPE_BROWSER      = 2;
//点击动作：打开Intent
exports.ACTION_TYPE_INTENT       = 3;
//点击动作：通过包名打开应用
exports.ACTION_TYPE_PACKAGE_NAME = 4;


//iOS环境：生产环境
exports.IOS_ENV_PRO = 1;
//iOS环境：生产
exports.IOS_ENV_DEV = 2;
// 开发环境

//-------常量定义 end---------

exports.XingeApp       = XingeApp;
exports.AndroidMessage = AndroidMessage;
exports.IOSMessage     = IOSMessage;
exports.TimeInterval   = TimeInterval;
exports.Style          = Style;
exports.ClickAction    = ClickAction;
