const express = require('express')
  , settings = require('../config/settings')
  // , db = require('./database')
  , mongoose = require('mongoose')
  , chalk = require('chalk')
var collections = {
  tx: require('../models/tx'),
  block: require('../models/block'),
  heavy: require('../models/heavy'),
  markets: require('../models/markets'),
  peers: require('../models/peers'),
  richlist: require('../models/richlist'),
  stats: require('../models/stats'),
}; Object.keys(collections).forEach(key => collections[key.toLowerCase()] = collections[key])

const log = true

const dapsapi = express()
// all routes are parsed into mongoose-like queries with the following format:
//
//   www .../dapsapi/block/?examplevar1=$lte:123$gte:456&examplevar2=456&limit=5&skip=2&sort=-height
//
//  /dapsapi/block/?    examplevar1= $lte:123 $gte:456    &   examplevar2=456   &   limit=5  &  skip=2    &  sort=-height
//
//          params[0] and reqcollection = block
//          limit per response = 5
//          skip 2 pages
//          sort in reverse order by height
//          query = {
//            examplevar1: {
//              '$lte': '456',                      examplevar1 <= 456 &&
//              '$gte': '123'                       examplevar1 >= 123
//            },
//            examplevar2: '789'                    examplevar2 = 789
//          }
//          
//        

dapsapi.get('*', async (req, res, next) => {
  // sterilize and parse req query and params
  let limit, skip, sort, count, report
  let queryObj = {}; Object.keys(req.query).forEach((key) =>
    queryObj[key.replace(/[^_\w]/g, '').toLowerCase()] = req.query[key].replace(/[^_\-$!.*^\[\]:\w]/g, ''))
  let reqcollection = req.params[0].toLowerCase().replace(/[^_\w]/g, '')
  try {
    limit = queryObj.limit ? queryObj.limit : 50; delete queryObj.limit;
    skip = queryObj.page ? ((queryObj.page - 1) * (limit || 1)) : 0; delete queryObj.page;
    count = queryObj.count ? queryObj.count : 0; if (count) limit = 0; delete queryObj.count;
    report = (queryObj.report!=undefined)? parseInt(queryObj.report) : log; delete queryObj.report;
    if (!skip) skip = queryObj.skip ? queryObj.skip : 0; delete queryObj.skip;
    if (skip < 0) skip = 0
    sort = queryObj['sort'] ? queryObj.sort : ''; delete queryObj['sort'];
    if (!sort.length)
      switch (reqcollection) {
        case "tx": sort = '-blockindex'; break;
        case "block": sort = '-height'; break;
      }
    for (key in queryObj) {
      if (queryObj[key].indexOf('$') != -1) {
        let subquery = queryObj[key].split('$').map((str) => {
          if (str.length) {
            if (str.indexOf(':') == -1) res.json({ status: 400, error: 'Invalid query', message: `Invalid advanced query. Try www .../dapsapi/[collection]/?examplevar=$gte:5$lte:10&examplevar2=$ne:6` })
            return { [`$${str.split(':')[0]}`]: str.split(':')[1] }
          }
        })
        queryObj[key] = {}
        subquery.forEach((subquery) => { queryObj[key] = Object.assign(queryObj[key], subquery) })
      }
    }
  } catch (err) { console.error("Error parsing query", err); res.send(err) }
  
  // query database and report result
  if (collections[reqcollection]) {
    if (report) {console.log(`${req.headers['x-forwarded-for'] || req.connection.remoteAddress}#    ${reqcollection}.find(${JSON.stringify(queryObj)}).sort(${sort}).limit(${parseInt(limit)}).skip(${parseInt(skip)})    count=${count}`)}
    if (count) {
      let result = await collections[reqcollection].count(queryObj, (err, found) => {
        queryObj = Object.assign(queryObj, { limit: parseInt(limit), skip: parseInt(skip), sort: sort, count: count })
        if (err) {
          console.error(err); res.json({ status: 400, error: err, query: queryObj, collection: reqcollection })
        } else if (!found) {
          if (report) console.log("    None found");
          res.json({ status: 404, error: "None found", query: queryObj, collection: reqcollection })
        } else {
          if (report) console.log(`    ${found} found`);
          res.json({ status: 200, data: found, query: queryObj, collection: reqcollection })
        }
      });

    } else {
      var aggregate = collections[reqcollection].aggregate();
      aggregate.match(queryObj).sort(sort);
      var options = { page : skip / 20 + 1, limit : 20, allowDiskUse: true };
      let result = await collections[reqcollection].aggregatePaginate(aggregate, options, (err, results, pageCount, cnt) => {
        queryObj = Object.assign(queryObj, { limit: parseInt(limit), skip: parseInt(skip), sort: sort, count: count })
        if (err) {
          console.error(err); res.json({ status: 400, error: err, query: queryObj, collection: reqcollection })
        } else if (!results.length) {
          if (report) console.log("    None found");
          res.json({ status: 404, error: "None found", query: queryObj, collection: reqcollection })
        } else {
          if (report) console.log(`    ${results.length} found`);
          res.json({ status: 200, data: !count ? results : results.length, query: queryObj, collection: reqcollection })
        }
      });
    }
  } else res.json({
    status: 418,
    teapot: true,
    query: queryObj,
    collection: reqcollection,
    error: 'Invalid collection request',
    message: `Invalid collection. Try www .../dapsapi/${Object.keys(collections).map(col => `[${col}]`).join(' ')}/?limit=5`
  })
})

module.exports = dapsapi;