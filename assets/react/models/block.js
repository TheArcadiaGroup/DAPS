var mongoose = require('mongoose')
    , Schema = mongoose.Schema
    ,mongooseAggregatePaginate = require('mongoose-aggregate-paginate-allowdiskuse');

var BlockSchema = new Schema({
    hash: { type: String, lowercase: true, unique: true },
    confirmations: { type: Number, default: 0 },
    size: { type: Number, default: 0 },
    height: { type: Number, unique: true },
    version: { type: Number, default: 0 },
    merkleroot: { type: String, lowercase: true },
    acc_checkpoint: { type: String, lowercase: true },
    tx: { type: Array, default: [] },
    time: { type: Number, default: 0 },
    nonce: { type: Number, default: 0 },
    bits: { type: String, lowercase: true },
    difficulty: { type: Number, default: 0 },
    chainwork: { type: String, lowercase: true },
    previousblockhash: { type: String, lowercase: true },
    moneysupply: { type: Number, default: 0 },
    blocktype: { type: String },
    numaudited: { type: Number, default: 0 },
    minetype: { type: String },
    sortid: {type: Number}
}, { id: false });

BlockSchema.plugin(mongooseAggregatePaginate);
BlockSchema.index({ hash: 1, sortid: -1 });

module.exports = mongoose.model('Block', BlockSchema);