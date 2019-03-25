var jsXss = require('xss');
var url = require('url');
var _ = require('underscore');

//默认配置，删除不在白名单中的标签和属性
var DEFAULT_CONFIG = {
    stripIgnoreTag: true,
    stripIgnoreTagBody: true
}

//默认配置，路由白名单列表和需要jsonParse的路由列表
var DEFAULT_ROUTER_CONFIG = {
    whiteList:[],
    jsonParseObject:{}
}
/**
 * 用js-xss 对html过滤
 *
 * @param {String} str
 * @return {String} str
 */
function filterHtml(str) {
    var xssObj = new jsXss.FilterXSS(DEFAULT_CONFIG);
    return xssObj.process(str);
}

/**
 * 参数过滤，对敏感字符进行转义
 *
 * @param {String} str
 * @return {object}
 *   - {Boolean} isMatched:是否匹配到敏感字符
 *   - {String}  value:过滤后的字符串
 *   - {String}  matchedChar:敏感字符
 */
function escapeParams(value,jsonParse,paramsArr){
    var isMatched = false;
    var matchedChar = '';

    //是否需要对json字符串进行parse
    if(jsonParse && typeof value === 'string') {
        try{
            value = JSON.parse(value);
        } catch(e) {

        }
    }
    if(typeof value === 'string'){
        value = value.replace(/[<>'"\\]/g,function(e){
            isMatched = true;
            matchedChar = e;
            return '&#'+e.charCodeAt()+';'
        })
    } else {
        value = escapeObject(value,jsonParse,paramsArr);
    }

    return {
        isMatched: isMatched,
        value: value,
        matchedChar: matchedChar
    }
}

/**
 * 递归过滤数组、对象中敏感字符
 */

function escapeObject (value,jsonParse,parmasArr) {
    if(jsonParse && typeof value === 'string') {
        try{
            value = JSON.parse(value);
        } catch(e) {

        }
    }

     var type = Object.prototype.toString.call(value);

     if(type === '[object Array]') {
         return value.map(function(item,index) {
             return escapeObject(item,jsonParse,parmasArr)
         })
     }

     if(type === '[object Object]') {
         for(var key in value) {
             var parseFlag = false;
             if(parmasArr && inArray(key,parmasArr)) {
                 parseFlag = true;
             }
             value[key] = escapeObject(value[key],parseFlag,parmasArr);
         }
         return value;
     }

     if(type === '[object String]') {
        return value.replace(/[<>'"\\]/g,function(e){
            return '&#'+e.charCodeAt()+';'
        })
     } else {
         return value;
     }
 }

/**
 * 对编码后的字符进行解码
 * @param str
 * @returns str
 */
function unescapeParams(value) {
    var type = Object.prototype.toString.call(value);

    if(type === '[object Array]') {
        return value.map(function(item,index) {
            return unescapeParams(item)
        })
    }

    if(type === '[object Object]') {
        for(var key in value) {
            value[key] = unescapeParams(value[key]);
        }
        return value;
    }

    if(type === '[object String]') {
       return value.replace(/&#(\d{2});/g, function (all, $1) {
        return String.fromCharCode($1);
        });
    } else {
        return value;
    }
}
/**
 * 判断是否是html结尾的参数名
 *
 * @param {String} param
 * @return {Boolean}
 */
function isHtmlParam(param) {
    var REGEXP_HTML = /(html)$/i;
    return REGEXP_HTML.test(param);
}

/**
 * 校验路由是否在list中
 */

function checkInList(url,list) {
    var flag = false;
    for(var i = 0; i < list.length; i++) {
        if(url.match(new RegExp(list[i]))) {
            flag = true;
            break;
        }
    }
    return flag;
}

/**
 * 当前路由是否有json字符串参数，返回参数名数组
 */

function checkJsonParam(url,object) {
    var arr = null;
    for(var key in object) {
        if(url.match(new RegExp(key))) {
            arr = object[key];
            break;
        }
    }
    return arr;
}

/**
 * 校验参数是否在数组中
 */

function inArray(value,array) {
    return array.indexOf(value) != -1;
}

module.exports = function (config,routerConfig) {

    if (config && typeof config === 'object') {
        _.extend(DEFAULT_CONFIG,config);
    }

    if(!routerConfig) {
        routerConfig = {};
    }

    if(routerConfig && typeof routerConfig === 'object') {
        routerConfig =  _.extend({},DEFAULT_ROUTER_CONFIG,routerConfig);
     }
 
    return function (req, res, next) {
        req.xss = {};
        req.xss.unescape = unescapeParams;
        req.xss.escape = function(str,parseFlag,parmasArr){
            return escapeParams(str,parseFlag,parmasArr).value;
        };

        //路由是否在白名单中
        if(checkInList(req.originalUrl,routerConfig.whiteList)) {
            next();
            return;
        }

        var keyArr = checkJsonParam(req.originalUrl,routerConfig.jsonParseObject);

        //过滤query参数
        for (var query in req.query) {
            if (query) {
                if (isHtmlParam(query)) {
                    req.query[query] = filterHtml(req.query[query]);
                }
                else {
                    req.query[query] = escapeParams(req.query[query],keyArr && inArray(query,keyArr),keyArr).value;
                }
            }
        }
        //过滤路由参数params
        if (req.url) {
            var pathname = url.parse(req.url).pathname;//获取req.url的路径，不包含query
            var decodePathname = decodeURI(pathname);//解码pathname
            var escapedParams = decodePathname.replace(/[<>'"\\]/g,'');//转义字符
            var urlObj = url.parse(req.url);
            var queryString = urlObj.query; //获取query
            // if(queryString) {
            //     var decodeQuery = decodeURI(queryString); //解码query
            //     var escapedQuery = escapeParams(decodeQuery); //转义query
            // }
            req.url = queryString ? encodeURI(escapedParams) + '?' + queryString: encodeURI(escapedParams);
        }
        //过滤body参数
        for (var body in req.body) {
            if (body) {
                if (isHtmlParam(body)) {
                    req.body[body] = filterHtml(req.body[body]);
                }
                else {
                    req.body[body] = escapeParams(req.body[body],keyArr && inArray(body,keyArr),keyArr).value;
                }
            }
        }
        next();
    }
};