// models/GasReading.js
const mongoose = require('mongoose');

const gasSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, index: true },
  value: { type: Number, required: true },
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('GasReading', gasSchema);
