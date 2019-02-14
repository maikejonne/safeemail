'use strict';
var express = require('express');//It's not necessary
var semail = require('./lib/semail');
var uploads = require('./lib/uploads');

const plugin = {};

plugin.init = function (params, callback) {
	const app = params.app;

	app.use("/semcmd", uploads);
	
	//
	app.use('/semail', express.static('./safemailforweb'));//It's not necessary
	
	var ModulesSockets = require.main.require('./src/socket.io/modules');
	var SockerIO = require.main.require('./src/socket.io');
	var io = SockerIO.server;
	semail.init(io);

	io.on("connection", function(socket) {
		semail.onConnect(socket);		
		socket.on('disconnect', function(){
			semail.onDisConnect(this);
		});
	});

	ModulesSockets.semail = function(socket, data, callback) {
		semail.onMessage(socket, data, callback);
	};

	callback();
};

module.exports = plugin;
