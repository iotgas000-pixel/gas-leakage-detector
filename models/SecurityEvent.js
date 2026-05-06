const mongoose = require('mongoose');

const securityEventSchema = new mongoose.Schema({
  deviceId: { type: String, index: true },
  eventType: {
    type: String,
    enum: ['FAILED_AUTH', 'REPLAY_ATTACK', 'ANOMALY_FLAT', 'ANOMALY_SPIKE', 'INVALID_VALUE'],
    required: true
  },
  ipAddress: String,
  details: String,
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('SecurityEvent', securityEventSchema);
