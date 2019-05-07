var mongoose = require('mongoose')
  , Schema = mongoose.Schema
  ,mongooseAggregatePaginate = require('mongoose-aggregate-paginate-allowdiskuse');
 
var RichlistSchema = new Schema({
  coin: { type: String },	
  received: { type: Array, default: []},
  balance: { type: Array, default: [] },
});

RichlistSchema.plugin(mongooseAggregatePaginate);
module.exports = mongoose.model('Richlist', RichlistSchema);