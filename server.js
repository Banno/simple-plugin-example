/*
 * Copyright 2020 Jack Henry & Associates, Inc.®
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This example plugin is best used when following along with the "Build Your First Plugin" quickstart,
// see more details https://jackhenry.dev/open-api-docs/plugins/quickstarts/BuildYourFirstPlugin/
//
// To learn more about extending Banno's user interface and how to get started with the Plugin Framework,
// see more details at https://jackhenry.dev/open-api-docs/plugins/getting-started/

const express = require('express')
const app = express()

const config = require('./config')
const authRouter = require('./routes/auth')

// set the view engine to ejs
app.set('view engine', 'ejs')

app.use('/public/', express.static('./public'));

app.use('/auth', authRouter)

app.get('/', (req, res) => {
    res.redirect('/static')
})

app.get('/static', (req, res) => {
    res.render('pages/static')
})

app.listen(config.app_port, () => {
    console.log(`App running at http://localhost:${config.app_port}`)
})