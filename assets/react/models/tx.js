var mongoose = require('mongoose')
  , Schema = mongoose.Schema
  ,mongooseAggregatePaginate = require('mongoose-aggregate-paginate-allowdiskuse');

var TxSchema = new Schema({
  txid: { type: String, lowercase: true, unique: true },
  vin: { type: Array, default: [] },
  vout: { type: Array, default: [] },
  total: { type: Number, default: 0 },
  timestamp: { type: Number, default: 0 },
  blockhash: { type: String },
  blockindex: { type: Number, default: 0 },
  blocktype: { type: String },
  confirmations: { type: Number, default: 0 },
  confirmationsneeded: { type: Number, default: 100 },
  blocktime: { type: Number, default: 0 },
  blocksize: { type: Number, default: 0 },
  locktime: { type: Number, default: 0 },
  scriptPubkey: { type: Object },
  txpubkey: { type: String},
  hex: { type: String },
  time: { type: Number, default: 0 },
  txfee: { type: String, default: '---' },
  ringsize: { type: Number, default: 0 },
  vin_raw: { type: Array, default: [] },
  vout_raw: { type: Array, default: [] },
  sortid: {type: String}
}, { id: false });

TxSchema.plugin(mongooseAggregatePaginate);
TxSchema.index({ txid: 1, sortid: -1 });
module.exports = mongoose.model('Tx', TxSchema);
