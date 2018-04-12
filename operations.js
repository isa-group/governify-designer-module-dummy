'use strict'

const yaml = require('js-yaml');
const request = require('request');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CSPTools = require("governify-csp-tools");
const CSPModel = CSPTools.CSPModel;
const Reasoner = CSPTools.Reasoner;
const DummyExecutor = CSPTools.DummyExecutor;
const CSPModelDummyTranslator = CSPTools.CSPModelDummyTranslator;
const DummyCSPModelTranslator = CSPTools.DummyCSPModelTranslator;
const annotationErrorFilter = /(.*dummy:.*|Dummy:\s+)/g;

module.exports = {

    hash: function (res, data, parameters) {
        let hash;
        try {
            let parsedData = yaml.safeLoad(data[0].content);
            let text = parsedData.content.toString();
            let secret = parsedData.config.secret.toString();
            let algorithm = parsedData.config.algorithm.toString();

            let hmac = crypto.createHmac(algorithm, secret);
            hmac.update(text);
            hash = hmac.digest('hex');
            res.status(200).json(new responseModel('OK', hash, hash, []));

        } catch (err) {
            res.status(200).json(new responseModel('ERROR', 'Error while hashing: ' + err, null, []));
        }

    },
    slowhash: function (res, data, parameters) {
        let hash;
        try {
            let parsedData = yaml.safeLoad(data[0].content);
            let text = parsedData.content.toString();
            let secret = parsedData.config.secret.toString();
            let algorithm = parsedData.config.algorithm.toString();
            let wait = parseInt(parsedData.config.wait);

            let hmac = crypto.createHmac(algorithm, secret);
            hmac.update(text);
            hash = hmac.digest('hex');

            setTimeout(function () {
                res.status(200).json(new responseModel('OK', hash, hash, []));
            }, wait);

        } catch (err) {
            res.status(200).json(new responseModel('ERROR', 'Error while hashing: ' + err, null, []));
        }

    },

    /// DEFAULT FUNCTIONS

    execute: function (res, data, parameters) {

        var cspModel = CSPModel.create(yaml.safeLoad(data[0].content));

        var reasoner = new Reasoner({
            type: 'local',
            folder: 'csp_files'
        });

        reasoner.solve(cspModel, (err, stdout, stderr, isSatisfiable, document) => {
            if (err || (parameters && parameters.format === "json")) {
                res.send({
                    error: err,
                    stdout: stdout,
                    stderr: stderr,
                    isSatisfiable: isSatisfiable,
                    document: document
                });
            } else {
                res.send(new responseModel('OK', getResponseModelCSP(stdout), data, null));
            }
        });

    },
    check: function (syntax, res, data) {
        switch (syntax) {
            case 'yaml':
                try {
                    yaml.safeLoad(data.content, 'utf8');
                    res.status(200).json(new responseModel('OK', null, null, null));
                } catch (e) {
                    var annotations = [new annotation('error', e.mark.line, e.mark.column, e.reason)];
                    res.status(200).json(new responseModel('OK_PROBLEMS', null, null, annotations));
                }
                break;
            case 'json':
                try {
                    JSON.parse(data.content, 'utf8');
                    res.status(200).json(new responseModel('OK', null, null, null));
                } catch (e) {
                    var annotations = [new annotation('error', e.mark.line, e.mark.column, e.reason)];
                    res.status(200).json(new responseModel('OK_PROBLEMS', null, null, annotations));
                }
                break;
        }
    },
    checkConsistency: function (syntax, res, data) {

        if (data.content === "") {

            // Nothing to do
            res.status(200).json(new responseModel('OK', null, null, null));

        } else {

            switch (syntax) {

                case 'dummy':

                    var dummyDocument = data.content;
                    var reasoner = new Reasoner({
                        type: 'local',
                        folder: 'csp_files'
                    });

                    reasoner.solve(dummyDocument, (err, stdout, stderr, isSatisfiable) => {
                        if (err) {

                            var re = /.*\.dummy:([0-9]+):.*/;
                            var annotations = [];
                            var errorMsgs = stderr.split(/\r?\n\r?\n/);

                            errorMsgs.forEach((errorMsg, index) => {
                                var group = re.exec(errorMsg);
                                if (group && group.length === 2) {
                                    let line = parseInt(group[1]) - 1;
                                    annotations.push(new annotation('error', line, 0, errorMsg.replace(annotationErrorFilter, "").trim()));
                                }
                            });

                            if (annotations.length > 0) {
                                res.status(200).json(new responseModel('OK_PROBLEMS', null, null, annotations));
                            } else {
                                res.status(200).json(new responseModel('OK_PROBLEMS', null, null, [new annotation('error', 0, 0, stderr ? stderr.replace(annotationErrorFilter, "").trim() : (typeof error === "object" && error.message) ? error.message.replace(annotationErrorFilter, "").trim() : "")]));
                            }

                        } else {
                            res.status(200).json(new responseModel('OK', null, null, null));
                        }
                    });

                    break;

                case 'yaml':

                    var cspModel = yaml.safeLoad(data.content);
                    var dummyDocument = new CSPModelDummyTranslator(cspModel).translate();

                    // Use these splitted documents to transform error indexes
                    var dummyDocumentSplitted = dummyDocument.split(/\r?\n/);
                    var yamlDocumentSplitted = data.content.split(/\r?\n/);

                    var reasoner = new Reasoner({
                        type: 'local',
                        folder: 'csp_files'
                    });

                    reasoner.solve(dummyDocument, (err, stdout, stderr, isSatisfiable) => {
                        if (err) {

                            var re = /.*\.dummy:([0-9]+):.*/;
                            var annotations = [];
                            var errorMsgs = stderr.split(/\r?\n\r?\n/);

                            errorMsgs.forEach((errorMsg, index) => {
                                var group = re.exec(errorMsg);
                                if (group && group.length === 2) {
                                    let dummyStatementErrorLine = parseInt(group[1]) - 1;
                                    let dummyStatement = dummyDocumentSplitted[dummyStatementErrorLine];
                                    let dummyStatementObj = new DummyCSPModelTranslator(dummyStatement).translate();
                                    let typeOfStatement = Object.keys(dummyStatementObj)[0];
                                    let statementId = (typeOfStatement === "goal") ?
                                        dummyStatementObj[typeOfStatement].id : dummyStatementObj[typeOfStatement][0].id;

                                    yamlDocumentSplitted.every((s, i) => {
                                        if (s.indexOf(statementId) !== -1) {
                                            annotations.push(new annotation('error', i, 0, errorMsg.replace(annotationErrorFilter, "").trim()));
                                            return false;
                                        } else {
                                            return true;
                                        }
                                    });

                                }
                            });

                            if (annotations.length > 0) {
                                res.status(200).json(new responseModel('OK_PROBLEMS', null, null, annotations));
                            } else {
                                res.status(200).json(new responseModel('OK_PROBLEMS', null, null, [new annotation('error', 0, 0, stderr ? stderr.replace(annotationErrorFilter, "").trim() : (typeof error === "object" && error.message) ? error.message.replace(annotationErrorFilter, "").trim() : "")]));
                            }

                        } else {
                            res.status(200).json(new responseModel('OK', null, null, null));
                        }
                    });

                    break;

                case 'json':

                    var cspModel = JSON.parse(data.content);
                    var dummyDocument = new CSPModelDummyTranslator(cspModel).translate();

                    // Use these splitted documents to transform error indexes
                    var dummyDocumentSplitted = dummyDocument.split(/\r?\n/);
                    var jsonDocumentSplitted = data.content.split(/\r?\n/);

                    var reasoner = new Reasoner({
                        type: 'local',
                        folder: 'csp_files'
                    });

                    reasoner.solve(dummyDocument, (err, stdout, stderr, isSatisfiable) => {
                        if (err) {

                            var re = /.*\.dummy:([0-9]+):.*/;
                            var annotations = [];
                            var errorMsgs = stderr.split(/\r?\n\r?\n/);

                            errorMsgs.forEach((errorMsg, index) => {
                                var group = re.exec(errorMsg);
                                if (group && group.length === 2) {
                                    let dummyStatementErrorLine = parseInt(group[1]) - 1;
                                    let dummyStatement = dummyDocumentSplitted[dummyStatementErrorLine];
                                    let dummyStatementObj = new DummyCSPModelTranslator(dummyStatement).translate();
                                    let typeOfStatement = Object.keys(dummyStatementObj)[0];
                                    let statementId = (typeOfStatement === "goal") ?
                                        dummyStatementObj[typeOfStatement].id : dummyStatementObj[typeOfStatement][0].id;

                                    jsonDocumentSplitted.every((s, i) => {
                                        if (s.indexOf(statementId) !== -1) {
                                            annotations.push(new annotation('error', i, 0, errorMsg.replace(annotationErrorFilter, "").trim()));
                                            return false;
                                        } else {
                                            return true;
                                        }
                                    });

                                }
                            });

                            if (annotations.length > 0) {
                                res.status(200).json(new responseModel('OK_PROBLEMS', null, null, annotations));
                            } else {
                                res.status(200).json(new responseModel('OK_PROBLEMS', null, null, [new annotation('error', 0, 0, stderr ? stderr.replace(annotationErrorFilter, "").trim() : (typeof error === "object" && error.message) ? error.message.replace(annotationErrorFilter, "").trim() : "")]));
                            }

                        } else {
                            res.status(200).json(new responseModel('OK', null, null, null));
                        }
                    });

                    break;
            }
        }
    },
    translate: function (syntaxSrc, syntaxDes, res, data) {

        if (data.content === "") {

            res.status(200).json(new responseModel('OK', "Nothing to translate", null, []));

        } else {

            switch (syntaxSrc) {
                case 'dummy':
                    if (syntaxDes === 'yaml') {

                        res.status(200).json(new responseModel('OK', 'The content has been translated',
                            yaml.safeDump(new DummyCSPModelTranslator(data.content).translate()), []));

                    } else if (syntaxDes === 'json') {

                        res.status(200).json(new responseModel('OK', 'The content has been translated',
                            JSON.stringify(new DummyCSPModelTranslator(data.content).translate(), null, 4), []));

                    } else {

                        translateCombinationError(res, syntaxDes);

                    }
                    break;
                case 'json':
                    if (syntaxDes === 'yaml') {

                        var dummyObject = JSON.parse(data.content);
                        res.status(200).json(new responseModel('OK', 'The content has been translated', yaml.safeDump(dummyObject), []));

                    } else if (syntaxDes === 'dummy') {

                        var dummyObject = JSON.parse(data.content);
                        res.status(200).json(new responseModel('OK', 'The content has been translated', new CSPModelDummyTranslator(dummyObject).translate(), []));

                    } else {

                        translateCombinationError(res, syntaxDes);

                    }
                    break;
                case 'yaml':
                    if (syntaxDes === 'dummy') {

                        var dummyObject = yaml.safeLoad(data.content, 'utf8');
                        res.status(200).json(new responseModel('OK', 'The content has been translated', new CSPModelDummyTranslator(dummyObject).translate(), []));

                    } else if (syntaxDes === 'json') {

                        var dummyObject = yaml.safeLoad(data.content);
                        res.status(200).json(new responseModel('OK', 'The content has been translated', JSON.stringify(dummyObject, null, 4), []));

                    } else {

                        translateCombinationError(res, syntaxDes);

                    }
                    break;
                default:
                    res.status(200).json(new responseModel('ERROR', "It is not possible to translate from " + syntaxSrc + " to " + syntaxDes, null, []));
            }

        }

    }
}

function translateCombinationError(res, syntaxDes) {
    res.status(200).json(new responseModel("ERROR", "It is not possible to translate from yaml to " + syntaxDes, null, []));
}

function responseModel(status, message, data, annotations) {
    this.status = status;
    this.message = message;
    this.data = data;
    this.annotations = annotations;
}

function annotation(type, row, column, text) {
    this.type = type;
    this.row = row;
    this.column = column;
    this.text = text;
}

let getResponseModelCSP = (stdout) => {
    return '<pre>' + stdout + '</pre>';
};