var mongoose = require('mongoose')
  , Schema = mongoose.Schema
  ,mongooseAggregatePaginate = require('mongoose-aggregate-paginate-allowdiskuse');
 
var MarketsSchema = new Schema({
  market: { type: String },
  summary: { type: Object, default: {} },
  chartdata: { type: Array, default: [] },
  buys: { type: Array, default: [] },
  sells: { type: Array, default: [] },
  history: { type: Array, default: [] },
});

MarketsSchema.plugin(mongooseAggregatePaginate);
module.exports = mongoose.model('Markets', MarketsSchema);