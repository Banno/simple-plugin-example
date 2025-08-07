const express = require('express')
const router = express.Router()
const { initAuth, handleCallback } = require('../controllers/authController')

router.get('/', initAuth)
router.get('/callback', handleCallback)

module.exports = router