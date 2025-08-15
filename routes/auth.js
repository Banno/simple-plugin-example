const express = require('express')
const router = express.Router()
const { initAuth, handleAuthCallback } = require('../controllers/authController')

router.get('/', initAuth)
router.get('/callback', handleAuthCallback)

module.exports = router